package oidc_test

import (
	"context"
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
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(publicJWKS)
	}))

	tsOtherJWKS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(publicJWKS2)
	}))
	makeClaims := func(aud string) jwt.RegisteredClaims {
		return jwt.RegisteredClaims{
			Issuer:    "https://login.microsoftonline.com/tenant_id/v2.0",
			Subject:   "acme@ory.sh",
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		}
	}
	t.Run("case=successful verification", func(t *testing.T) {
		_, reg := internal.NewVeryFastRegistryWithoutDB(t)
		apple := oidc.NewProviderMicrosoft(&oidc.Configuration{
			ClientID: "com.example.app",
			Tenant:   "tenant_id_fake",
		}, reg).(*oidc.ProviderMicrosoft)
		apple.JWKSUrl = ts.URL
		token := createIdToken(t, makeClaims("com.example.app"))

		c, err := apple.Verify(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, "acme@ory.sh", c.Email)
		assert.Equal(t, "acme@ory.sh", c.Subject)
		assert.Equal(t, "https://login.microsoftonline.com/tenant_id/v2.0", c.Issuer)
	})

	t.Run("case=fails due to client_id mismatch", func(t *testing.T) {
		_, reg := internal.NewFastRegistryWithMocks(t)
		apple := oidc.NewProviderMicrosoft(&oidc.Configuration{
			ClientID: "com.example.app",
			Tenant:   "tenant_id",
		}, reg).(*oidc.ProviderMicrosoft)
		apple.JWKSUrl = ts.URL
		token := createIdToken(t, makeClaims("com.different-example.app"))

		_, err := apple.Verify(context.Background(), token)
		require.Error(t, err)
		assert.Equal(t, `token audience didn't match allowed audiences: [com.example.app] oidc: expected audience "com.example.app" got ["com.different-example.app"]`, err.Error())
	})

	t.Run("case=fails due to jwks mismatch", func(t *testing.T) {
		_, reg := internal.NewFastRegistryWithMocks(t)
		apple := oidc.NewProviderMicrosoft(&oidc.Configuration{
			ClientID: "com.example.app",
			Tenant:   "tenant_id",
		}, reg).(*oidc.ProviderMicrosoft)
		apple.JWKSUrl = tsOtherJWKS.URL
		token := createIdToken(t, makeClaims("com.example.app"))

		_, err := apple.Verify(context.Background(), token)
		require.Error(t, err)
		assert.Equal(t, "failed to verify signature: failed to verify id token signature", err.Error())
	})

	t.Run("case=fails due to wrong issuer tenant", func(t *testing.T) {
		_, reg := internal.NewFastRegistryWithMocks(t)
		apple := oidc.NewProviderMicrosoft(&oidc.Configuration{
			ClientID: "com.example.app",
			Tenant:   "wrong_tenant_id",
		}, reg).(*oidc.ProviderMicrosoft)
		apple.JWKSUrl = tsOtherJWKS.URL
		token := createIdToken(t, makeClaims("com.example.app"))

		_, err := apple.Verify(context.Background(), token)
		require.Error(t, err)
		assert.Equal(t, "oidc: id token issued by a different provider, expected \"https://login.microsoftonline.com/wrong_tenant_id/v2.0\" got \"https://login.microsoftonline.com/tenant_id/v2.0\"", err.Error())
	})

	t.Run("case=succeedes with additional id token audience", func(t *testing.T) {
		_, reg := internal.NewFastRegistryWithMocks(t)
		apple := oidc.NewProviderMicrosoft(&oidc.Configuration{
			ClientID:                   "something.else.app",
			Tenant:                     "tenant_id",
			AdditionalIDTokenAudiences: []string{"com.example.app"},
		}, reg).(*oidc.ProviderMicrosoft)
		apple.JWKSUrl = ts.URL
		token := createIdToken(t, makeClaims("com.example.app"))

		_, err := apple.Verify(context.Background(), token)
		require.NoError(t, err)
	})

	makeClaimsWithOID := func(oid string) *claims {
		cl := makeClaims("com.example.app")
		return &claims{RegisteredClaims: &cl, Email: "acme@ory.sh", Object: oid}
	}
	newProvider := func(t *testing.T, subjectSource string) *oidc.ProviderMicrosoft {
		_, reg := internal.NewFastRegistryWithMocks(t)
		p := oidc.NewProviderMicrosoft(&oidc.Configuration{
			ClientID:      "com.example.app",
			Tenant:        "tenant_id",
			SubjectSource: subjectSource,
		}, reg).(*oidc.ProviderMicrosoft)
		p.JWKSUrl = ts.URL
		return p
	}

	t.Run("case=uses oid as subject when subject_source is oid", func(t *testing.T) {
		c, err := newProvider(t, "oid").Verify(context.Background(), signIdToken(t, makeClaimsWithOID("00000000-0000-0000-0000-00000000c0de")))
		require.NoError(t, err)
		assert.Equal(t, "00000000-0000-0000-0000-00000000c0de", c.Subject)
	})

	t.Run("case=keeps sub as subject when subject_source is default", func(t *testing.T) {
		c, err := newProvider(t, "").Verify(context.Background(), signIdToken(t, makeClaimsWithOID("00000000-0000-0000-0000-00000000c0de")))
		require.NoError(t, err)
		assert.Equal(t, "acme@ory.sh", c.Subject)
	})

	t.Run("case=fails when subject_source is oid and the oid claim is missing", func(t *testing.T) {
		_, err := newProvider(t, "oid").Verify(context.Background(), signIdToken(t, makeClaimsWithOID("")))
		require.Error(t, err)
		var herr *herodot.DefaultError
		require.ErrorAs(t, err, &herr)
		assert.Equal(t, http.StatusBadRequest, herr.StatusCode())
		assert.Contains(t, herr.Reason(), "`oid` claim")
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
}
