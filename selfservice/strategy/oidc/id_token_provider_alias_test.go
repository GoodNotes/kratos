// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/strategy/oidc"
)

func TestIDTokenProviderAliasesNativeRequests(t *testing.T) {
	for _, entry := range []string{"login", "registration"} {
		t.Run(entry, func(t *testing.T) {
			ctx := context.Background()
			conf, reg := internal.NewFastRegistryWithMocks(t)
			jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(publicJWKS)
			}))
			t.Cleanup(jwks.Close)
			oidc.RegisterTestGoogleProvider(t, "test-google", jwks.URL)
			provider := oidc.Configuration{
				ID: "google-goodsystems", Provider: "test-google",
				ClientID: "goodmeet-client", Mapper: "file://./stub/oidc.hydra.jsonnet", PKCE: "never",
			}
			viperSetProviderConfig(t, conf, provider)
			conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+".oidc.config", &oidc.ConfigurationCollection{
				Providers:              []oidc.Configuration{provider},
				IDTokenProviderAliases: map[string]string{"google": "google-goodsystems"},
			})
			conf.MustSet(ctx, config.ViperKeySelfServiceRegistrationEnabled, true)
			testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/stub.schema.json")
			conf.MustSet(ctx, config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter, identity.CredentialsTypeOIDC.String()), []config.SelfServiceHook{{Name: "session"}})
			server, _ := testhelpers.NewKratosServer(t, reg)

			subject := "goodmeet-" + entry + "@example.test"
			classic := identity.NewIdentity("default")
			classic.Traits = identity.Traits(`{"subject":"` + subject + `"}`)
			classicCredentials, err := identity.NewCredentialsOIDC(new(identity.CredentialsOIDCEncryptedTokens), "google", subject, "")
			require.NoError(t, err)
			classic.SetCredentials(identity.CredentialsTypeOIDC, *classicCredentials)
			require.NoError(t, reg.IdentityManager().Create(ctx, classic))

			token := createIdToken(t, jwt.RegisteredClaims{
				Issuer: "https://accounts.google.com", Subject: subject,
				Audience: jwt.ClaimStrings{"goodmeet-client"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			})
			client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
			submit := func(providerID, idToken string) (int, []byte) {
				t.Helper()
				response, err := client.Get(server.URL + "/self-service/" + entry + "/api")
				require.NoError(t, err)
				flowBody, err := io.ReadAll(response.Body)
				require.NoError(t, response.Body.Close())
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, response.StatusCode, "%s", flowBody)
				action := gjson.GetBytes(flowBody, "ui.action").String()
				require.NotEmpty(t, action)
				payload, err := json.Marshal(map[string]string{"method": "OIDC", "provider": providerID, "id_token": idToken})
				require.NoError(t, err)
				request, err := http.NewRequest(http.MethodPost, action, strings.NewReader(string(payload)))
				require.NoError(t, err)
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Accept", "application/json")
				response, err = client.Do(request)
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				require.NoError(t, response.Body.Close())
				require.NoError(t, err)
				return response.StatusCode, body
			}
			var productID string
			for _, providerID := range []string{"google", "google-goodsystems", "google"} {
				status, body := submit(providerID, token)
				require.Equal(t, http.StatusOK, status, "%s", body)
				require.NotEmpty(t, gjson.GetBytes(body, "session_token").String())
				actualID := gjson.GetBytes(body, "session.identity.id").String()
				require.NotEmpty(t, actualID)
				assert.NotEqual(t, classic.ID.String(), actualID)
				assert.Equal(t, "google-goodsystems", gjson.GetBytes(body, "session.authentication_methods.0.provider").String())
				if productID == "" {
					productID = actualID
				} else {
					assert.Equal(t, productID, actualID)
				}

				product, _, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypeOIDC, "google-goodsystems:"+subject)
				require.NoError(t, err)
				assert.Equal(t, productID, product.ID.String())
				original, _, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypeOIDC, "google:"+subject)
				require.NoError(t, err)
				assert.Equal(t, classic.ID, original.ID)
			}

			// A browser-style submission has no ID token, so its provider stays exact.
			status, body := submit("google", "")
			require.Equal(t, http.StatusNotFound, status, "%s", body)
			assert.Contains(t, string(body), "unknown or has not been configured")

			status, body = submit("google", "invalid-id-token")
			require.GreaterOrEqual(t, status, http.StatusBadRequest, "%s", body)
			assert.Contains(t, string(body), "Could not verify id_token")
			assert.Empty(t, gjson.GetBytes(body, "session_token").String())

			// A product deployment without the opt-in does not accept legacy Google.
			conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+".oidc.config", &oidc.ConfigurationCollection{Providers: []oidc.Configuration{provider}})
			status, body = submit("google", token)
			require.Equal(t, http.StatusNotFound, status, "%s", body)
			status, body = submit("google-goodsystems", token)
			require.Equal(t, http.StatusOK, status, "%s", body)
			assert.Equal(t, productID, gjson.GetBytes(body, "session.identity.id").String())

			// Classic still authenticates its original identity with the same subject.
			provider.ID = "google"
			conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+".oidc.config", &oidc.ConfigurationCollection{Providers: []oidc.Configuration{provider}})
			status, body = submit("google", token)
			require.Equal(t, http.StatusOK, status, "%s", body)
			assert.Equal(t, classic.ID.String(), gjson.GetBytes(body, "session.identity.id").String())
			assert.Equal(t, "google", gjson.GetBytes(body, "session.authentication_methods.0.provider").String())
		})
	}
}
