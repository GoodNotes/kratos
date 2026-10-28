// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
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
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/strategy/oidc"
	"github.com/ory/kratos/x"
)

func TestPublicProviderIDNativeTokenRequests(t *testing.T) {
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
			viperSetProviderConfig(t, conf, oidc.Configuration{
				ID: "google-goodsystems", PublicID: "google", Provider: "test-google",
				ClientID: "goodmeet-client", Mapper: "file://./stub/oidc.hydra.jsonnet", PKCE: "never",
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
			var productID string
			for _, providerID := range []string{"google", "google-goodsystems", "google"} {
				response, err := client.Get(server.URL + "/self-service/" + entry + "/api")
				require.NoError(t, err)
				flowBody, err := io.ReadAll(response.Body)
				require.NoError(t, response.Body.Close())
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, response.StatusCode, "%s", flowBody)
				action := gjson.GetBytes(flowBody, "ui.action").String()
				require.NotEmpty(t, action)
				payload, err := json.Marshal(map[string]string{"method": "OIDC", "provider": providerID, "id_token": token})
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
				require.Equal(t, http.StatusOK, response.StatusCode, "%s", body)
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
		})
	}
}

func TestPublicProviderIDBrowserCallbacks(t *testing.T) {
	for _, selection := range []string{"form", "query"} {
		t.Run(selection, func(t *testing.T) {
			ctx := context.Background()
			conf, reg := internal.NewFastRegistryWithMocks(t)
			const subject = "browser-goodmeet@example.test"
			var issuer *httptest.Server
			var callback string
			var browserToken string
			issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"issuer": issuer.URL, "authorization_endpoint": issuer.URL + "/authorize",
						"token_endpoint": issuer.URL + "/token", "jwks_uri": issuer.URL + "/keys",
						"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
						"id_token_signing_alg_values_supported": []string{"RS256"},
					})
				case "/keys":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(publicJWKS)
				case "/authorize":
					if r.URL.Query().Get("redirect_uri") != callback {
						http.Error(w, "unregistered callback", http.StatusBadRequest)
						return
					}
					destination, _ := url.Parse(callback)
					query := destination.Query()
					query.Set("code", "synthetic-code")
					query.Set("state", r.URL.Query().Get("state"))
					destination.RawQuery = query.Encode()
					http.Redirect(w, r, destination.String(), http.StatusSeeOther)
				case "/token":
					_ = r.ParseForm()
					if r.Form.Get("redirect_uri") != callback || r.Form.Get("code") != "synthetic-code" {
						http.Error(w, "invalid code exchange", http.StatusBadRequest)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "synthetic-token", "token_type": "Bearer", "id_token": browserToken})
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(issuer.Close)
			browserToken = createIdToken(t, jwt.RegisteredClaims{
				Issuer: issuer.URL, Subject: subject, Audience: jwt.ClaimStrings{"goodmeet-client"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			})
			viperSetProviderConfig(t, conf, oidc.Configuration{
				ID: "google-goodsystems", PublicID: "google", Provider: "generic", ClientID: "goodmeet-client",
				ClientSecret: "synthetic-test-secret", IssuerURL: issuer.URL, Mapper: "file://./stub/oidc.hydra.jsonnet", PKCE: "never",
			})
			conf.MustSet(ctx, config.ViperKeySelfServiceRegistrationEnabled, true)
			testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/stub.schema.json")
			conf.MustSet(ctx, config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter, identity.CredentialsTypeOIDC.String()), []config.SelfServiceHook{{Name: "session"}})
			conf.MustSet(ctx, config.ViperKeyClientHTTPNoPrivateIPRanges, false)
			server, _ := testhelpers.NewKratosServer(t, reg)
			callback = server.URL + "/self-service/methods/oidc/callback/google"
			conf.MustSet(ctx, config.ViperKeySelfServiceLoginUI, server.URL+"/login-ui")
			conf.MustSet(ctx, config.ViperKeySelfServiceBrowserDefaultReturnTo, server.URL+"/finished")
			conf.MustSet(ctx, config.ViperKeyURLsAllowedReturnToDomains, []string{server.URL})
			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			client := &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

			response, err := client.Get(server.URL + "/self-service/login/browser")
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, http.StatusSeeOther, response.StatusCode)
			location, err := response.Location()
			require.NoError(t, err)
			flowID := location.Query().Get("flow")
			require.NotEmpty(t, flowID)
			response, err = client.Get(server.URL + "/self-service/login/flows?id=" + flowID)
			require.NoError(t, err)
			raw, err := io.ReadAll(response.Body)
			require.NoError(t, response.Body.Close())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, response.StatusCode, "%s", raw)
			assert.Equal(t, "google", gjson.GetBytes(raw, `ui.nodes.#(attributes.name=="provider").attributes.value`).String())
			action := gjson.GetBytes(raw, "ui.action").String()
			form := url.Values{"method": {"oidc"}, "csrf_token": {"fake-csrf-token"}}
			if selection == "form" {
				form.Set("provider", "google")
			} else {
				action += "&provider=google"
			}
			response, err = client.PostForm(action, form)
			require.NoError(t, err)
			raw, err = io.ReadAll(response.Body)
			require.NoError(t, response.Body.Close())
			require.NoError(t, err)
			require.Equal(t, http.StatusSeeOther, response.StatusCode, "%s", raw)
			authorize, err := response.Location()
			require.NoError(t, err)
			assert.Equal(t, callback, authorize.Query().Get("redirect_uri"))
			response, err = client.Get(authorize.String())
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, http.StatusSeeOther, response.StatusCode)
			returned, err := response.Location()
			require.NoError(t, err)
			assert.Equal(t, "/self-service/methods/oidc/callback/google", returned.Path)
			mismatch := *returned
			mismatch.Path = "/self-service/methods/oidc/callback/google-goodsystems"
			request, err := http.NewRequest(http.MethodGet, mismatch.String(), nil)
			require.NoError(t, err)
			request.Header.Set("Accept", "application/json")
			response, err = client.Do(request)
			require.NoError(t, err)
			raw, err = io.ReadAll(response.Body)
			require.NoError(t, response.Body.Close())
			require.NoError(t, err)
			require.Equal(t, http.StatusBadRequest, response.StatusCode, "%s", raw)
			assert.Contains(t, string(raw), "provider mismatch")
			response, err = client.Get(returned.String())
			require.NoError(t, err)
			raw, err = io.ReadAll(response.Body)
			require.NoError(t, response.Body.Close())
			require.NoError(t, err)
			require.Equal(t, http.StatusSeeOther, response.StatusCode, "%s", raw)
			finished, err := response.Location()
			require.NoError(t, err)
			assert.Equal(t, "/finished", finished.Path)
			response, err = client.Get(server.URL + "/sessions/whoami")
			require.NoError(t, err)
			raw, err = io.ReadAll(response.Body)
			require.NoError(t, response.Body.Close())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, response.StatusCode, "%s", raw)
			assert.Equal(t, "google-goodsystems", gjson.GetBytes(raw, "authentication_methods.0.provider").String())
			product, _, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypeOIDC, "google-goodsystems:"+subject)
			require.NoError(t, err)
			assert.Equal(t, product.ID.String(), gjson.GetBytes(raw, "identity.id").String())
		})
	}
}

func TestPublicProviderIDIdentifierFirstForm(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/stub.schema.json")
	conf.MustSet(ctx, config.ViperKeySecurityAccountEnumerationMitigate, false)
	viperSetProviderConfig(t, conf, oidc.Configuration{
		ID: "google-goodsystems", PublicID: "google", Provider: "google", ClientID: "goodmeet-client",
	})
	id := createIdentity(t, ctx, reg, x.NewUUID(), "google-goodsystems")
	request := httptest.NewRequest(http.MethodGet, "/self-service/login/browser", nil)
	f, err := login.NewFlow(conf, time.Minute, "csrf", request, flow.TypeBrowser)
	require.NoError(t, err)
	require.NoError(t, oidc.NewStrategy(reg).PopulateLoginMethodIdentifierFirstCredentials(request, f, login.WithIdentityHint(id)))
	raw, err := json.Marshal(f.UI.Nodes)
	require.NoError(t, err)
	assert.Equal(t, "google", gjson.GetBytes(raw, `#(attributes.name=="provider").attributes.value`).String())
}
