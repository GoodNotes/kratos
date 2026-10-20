// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	_ "embed"

	"github.com/golang-jwt/jwt/v4"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/ory/herodot"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/selfservice/strategy/oidc"
)

func TestMicrosoftVerify(t *testing.T) {
	const tenantA = "a9b86385-f32c-4803-afc8-4b2312fbdf24"
	const tenantB = "0b6c6f3e-5d2a-4c1b-9e8f-7a6b5c4d3e2f"
	issuerFor := func(tid string) string { return "https://login.microsoftonline.com/" + tid + "/v2.0" }

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(publicJWKS)
	}))

	tsOtherJWKS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(publicJWKS2)
	}))
	makeClaims := func(aud, tid string) *claims {
		return &claims{
			RegisteredClaims: &jwt.RegisteredClaims{
				Issuer:    issuerFor(tid),
				Subject:   "acme@ory.sh",
				Audience:  jwt.ClaimStrings{aud},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			},
			Email:    "acme@ory.sh",
			TenantID: tid,
		}
	}
	newProvider := func(t *testing.T, config *oidc.Configuration) *oidc.ProviderMicrosoft {
		_, reg := internal.NewFastRegistryWithMocks(t)
		if config.ClientID == "" {
			config.ClientID = "com.example.app"
		}
		p := oidc.NewProviderMicrosoft(config, reg).(*oidc.ProviderMicrosoft)
		p.JWKSUrl = ts.URL
		return p
	}
	requireBadRequest := func(t *testing.T, err error, reason string) *herodot.DefaultError {
		var herr *herodot.DefaultError
		require.ErrorAs(t, err, &herr)
		assert.Equal(t, http.StatusBadRequest, herr.StatusCode())
		assert.Contains(t, herr.Reason(), reason)
		return herr
	}

	t.Run("case=successful verification", func(t *testing.T) {
		c, err := newProvider(t, &oidc.Configuration{Tenant: tenantA}).Verify(context.Background(), signIdToken(t, makeClaims("com.example.app", tenantA)))
		require.NoError(t, err)
		assert.Equal(t, "acme@ory.sh", c.Email)
		assert.Equal(t, "acme@ory.sh", c.Subject)
		assert.Equal(t, issuerFor(tenantA), c.Issuer)
	})

	t.Run("case=preserves verified raw claims for the mapper", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			value interface{}
		}{
			{name: "boolean true", value: true},
			{name: "boolean false", value: false},
			{name: "string one", value: "1"},
			{name: "string zero", value: "0"},
			{name: "string true", value: "true"},
			{name: "string false", value: "false"},
			{name: "number one", value: float64(1)},
			{name: "number zero", value: float64(0)},
			{name: "absent"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cl := makeClaimsWithRawClaims(issuerFor(tenantA), tenantA, tc.value)
				c, err := newProvider(t, &oidc.Configuration{
					Tenant: tenantA, SubjectSource: "oid",
				}).Verify(context.Background(), signIdToken(t, cl))
				require.NoError(t, err)
				require.NotEmpty(t, c.RawClaims)

				// The mapper receives the JSON-encoded Claims object, not the JWT.
				encoded, err := json.Marshal(c)
				require.NoError(t, err)
				var mapperClaims map[string]interface{}
				require.NoError(t, json.Unmarshal(encoded, &mapperClaims))
				raw := mapperClaims["raw_claims"].(map[string]interface{})
				if tc.value == nil {
					assert.NotContains(t, raw, "xms_edov")
				} else {
					assert.Equal(t, tc.value, raw["xms_edov"])
				}
				assert.Equal(t, cl.Object, c.Subject)
				assert.Equal(t, cl.Subject, raw["sub"])
				assert.Equal(t, cl.Object, raw["oid"])
				assert.Equal(t, cl.Email, c.Email)
				assert.Equal(t, cl.TenantID, raw["tid"])
			})
		}
	})

	t.Run("case=rejects expired tokens even with xms_edov", func(t *testing.T) {
		cl := makeClaimsWithRawClaims(issuerFor(tenantA), tenantA, "1")
		cl.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		c, err := newProvider(t, &oidc.Configuration{Tenant: tenantA}).Verify(context.Background(), signIdToken(t, cl))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token is expired")
		assert.Nil(t, c)
	})

	t.Run("case=fails due to client_id mismatch", func(t *testing.T) {
		_, err := newProvider(t, &oidc.Configuration{Tenant: tenantA}).Verify(context.Background(), signIdToken(t, makeClaims("com.different-example.app", tenantA)))
		require.Error(t, err)
		assert.Equal(t, `token audience didn't match allowed audiences: [com.example.app] oidc: expected audience "com.example.app" got ["com.different-example.app"]`, err.Error())
	})

	t.Run("case=fails due to jwks mismatch", func(t *testing.T) {
		p := newProvider(t, &oidc.Configuration{Tenant: tenantA})
		p.JWKSUrl = tsOtherJWKS.URL

		_, err := p.Verify(context.Background(), signIdToken(t, makeClaims("com.example.app", tenantA)))
		require.Error(t, err)
		assert.Equal(t, "failed to verify signature: failed to verify id token signature", err.Error())
	})

	t.Run("case=fails due to wrong issuer tenant", func(t *testing.T) {
		_, err := newProvider(t, &oidc.Configuration{Tenant: tenantB}).Verify(context.Background(), signIdToken(t, makeClaims("com.example.app", tenantA)))
		herr := requireBadRequest(t, err, tenantA)
		// The pin runs before the signature check, so the reason must not leak the configured tenant.
		assert.NotContains(t, herr.Reason(), tenantB)
	})

	for _, tenant := range []string{"common", "organizations", "consumers", "contoso.onmicrosoft.com"} {
		t.Run("case=accepts any tenant when tenant is "+tenant, func(t *testing.T) {
			c, err := newProvider(t, &oidc.Configuration{Tenant: tenant}).Verify(context.Background(), signIdToken(t, makeClaims("com.example.app", tenantB)))
			require.NoError(t, err)
			assert.Equal(t, issuerFor(tenantB), c.Issuer)
		})
	}

	t.Run("case=fails when issuer does not match the tid claim", func(t *testing.T) {
		for _, iss := range []string{issuerFor(tenantB), "https://sts.windows.net/" + tenantA + "/"} {
			cl := makeClaims("com.example.app", tenantA)
			cl.Issuer = iss
			_, err := newProvider(t, &oidc.Configuration{Tenant: "common"}).Verify(context.Background(), signIdToken(t, cl))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "oidc: id token issued by a different provider")
		}
	})

	t.Run("case=fails when the tid claim is not a valid UUID", func(t *testing.T) {
		for _, tid := range []string{"", "tenant_id"} {
			_, err := newProvider(t, &oidc.Configuration{Tenant: "common"}).Verify(context.Background(), signIdToken(t, makeClaims("com.example.app", tid)))
			requireBadRequest(t, err, "TenantID claim is not a valid UUID")
		}
	})

	t.Run("case=fetches the JWKS with the registry HTTP client", func(t *testing.T) {
		const jwksURL = "https://jwks.microsoft.test/keys"
		_, base := internal.NewFastRegistryWithMocks(t)
		reg := &mockRegistry{base, retryablehttp.NewClient()}
		httpmock.ActivateNonDefault(reg.cl.HTTPClient)
		t.Cleanup(httpmock.DeactivateAndReset)
		httpmock.RegisterResponder("GET", jwksURL, httpmock.NewBytesResponder(200, publicJWKS))

		p := oidc.NewProviderMicrosoft(&oidc.Configuration{ClientID: "com.example.app", Tenant: tenantA}, reg).(*oidc.ProviderMicrosoft)
		p.JWKSUrl = jwksURL
		_, err := p.Verify(context.Background(), signIdToken(t, makeClaims("com.example.app", tenantA)))
		require.NoError(t, err)
	})

	t.Run("case=succeedes with additional id token audience", func(t *testing.T) {
		_, err := newProvider(t, &oidc.Configuration{
			ClientID:                   "something.else.app",
			Tenant:                     tenantA,
			AdditionalIDTokenAudiences: []string{"com.example.app"},
		}).Verify(context.Background(), signIdToken(t, makeClaims("com.example.app", tenantA)))
		require.NoError(t, err)
	})

	makeClaimsWithOID := func(oid string) *claims {
		cl := makeClaims("com.example.app", tenantA)
		cl.Object = oid
		return cl
	}
	newProviderWithSubjectSource := func(t *testing.T, subjectSource string) *oidc.ProviderMicrosoft {
		return newProvider(t, &oidc.Configuration{Tenant: tenantA, SubjectSource: subjectSource})
	}

	t.Run("case=uses oid as subject when subject_source is oid", func(t *testing.T) {
		c, err := newProviderWithSubjectSource(t, "oid").Verify(context.Background(), signIdToken(t, makeClaimsWithOID("00000000-0000-0000-0000-00000000c0de")))
		require.NoError(t, err)
		assert.Equal(t, "00000000-0000-0000-0000-00000000c0de", c.Subject)
	})

	t.Run("case=keeps sub as subject when subject_source is default", func(t *testing.T) {
		c, err := newProviderWithSubjectSource(t, "").Verify(context.Background(), signIdToken(t, makeClaimsWithOID("00000000-0000-0000-0000-00000000c0de")))
		require.NoError(t, err)
		assert.Equal(t, "acme@ory.sh", c.Subject)
	})

	t.Run("case=fails when subject_source is oid and the oid claim is missing", func(t *testing.T) {
		_, err := newProviderWithSubjectSource(t, "oid").Verify(context.Background(), signIdToken(t, makeClaimsWithOID("")))
		requireBadRequest(t, err, "`oid` claim")
	})
}

func TestMicrosoftClaims(t *testing.T) {
	const tenant = "a9b86385-f32c-4803-afc8-4b2312fbdf24"
	const issuer = "https://login.microsoftonline.com/" + tenant + "/v2.0"

	_, base := internal.NewFastRegistryWithMocks(t)
	reg := &mockRegistry{base, retryablehttp.NewClient()}
	httpmock.ActivateNonDefault(reg.cl.HTTPClient)
	t.Cleanup(httpmock.DeactivateAndReset)
	httpmock.RegisterResponder("GET", issuer+"/.well-known/openid-configuration",
		httpmock.NewJsonResponderOrPanic(200, map[string]interface{}{"issuer": issuer, "jwks_uri": issuer + "/keys"}))
	httpmock.RegisterResponder("GET", issuer+"/keys", httpmock.NewBytesResponder(200, publicJWKS))

	provider := oidc.NewProviderMicrosoft(&oidc.Configuration{
		ID:            "microsoft",
		Provider:      "microsoft",
		Tenant:        tenant,
		ClientID:      "foo",
		SubjectSource: "oid",
	}, reg).(oidc.OAuth2Provider)

	exchangeWithOID := func(t *testing.T, oid string) *oauth2.Token {
		idToken := signIdToken(t, &claims{
			RegisteredClaims: &jwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "pairwise-sub",
				Audience:  jwt.ClaimStrings{"foo"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Object:   oid,
			TenantID: tenant,
		})
		return (&oauth2.Token{AccessToken: "foo"}).WithExtra(map[string]interface{}{"id_token": idToken})
	}

	t.Run("case=uses oid as subject when subject_source is oid", func(t *testing.T) {
		c, err := provider.Claims(context.Background(), exchangeWithOID(t, "00000000-0000-0000-0000-00000000c0de"), url.Values{})
		require.NoError(t, err)
		assert.Equal(t, "00000000-0000-0000-0000-00000000c0de", c.Subject)
	})

	t.Run("case=fails when subject_source is oid and the oid claim is missing", func(t *testing.T) {
		_, err := provider.Claims(context.Background(), exchangeWithOID(t, ""), url.Values{})
		require.Error(t, err)
		var herr *herodot.DefaultError
		require.ErrorAs(t, err, &herr)
		assert.Equal(t, http.StatusBadRequest, herr.StatusCode())
		assert.Contains(t, herr.Reason(), "`oid` claim")
	})

	t.Run("case=browser and native expose the same verified claims", func(t *testing.T) {
		for _, value := range []interface{}{true, false, "1", "0", float64(1), nil} {
			cl := makeClaimsWithRawClaims(issuer, tenant, value)
			cl.Audience = jwt.ClaimStrings{"foo"}
			raw := signIdToken(t, cl)
			exchange := (&oauth2.Token{AccessToken: "foo"}).WithExtra(map[string]interface{}{"id_token": raw})
			browserClaims, err := provider.Claims(context.Background(), exchange, url.Values{})
			require.NoError(t, err)

			native := provider.(*oidc.ProviderMicrosoft)
			native.JWKSUrl = issuer + "/keys"
			nativeClaims, err := native.Verify(context.Background(), raw)
			require.NoError(t, err)
			assert.Equal(t, browserClaims, nativeClaims)
		}
	})
}

func makeClaimsWithRawClaims(issuer, tenant string, xmsEdov interface{}) *claims {
	return &claims{
		RegisteredClaims: &jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "pairwise-sub",
			Audience:  jwt.ClaimStrings{"com.example.app"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email:    "acme@ory.sh",
		Object:   "00000000-0000-0000-0000-00000000c0de",
		TenantID: tenant,
		XmsEdov:  xmsEdov,
	}
}
