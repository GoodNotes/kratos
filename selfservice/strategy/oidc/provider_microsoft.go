// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/ory/x/httpx"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/ory/herodot"
)

type ProviderMicrosoft struct {
	*ProviderGenericOIDC
	JWKSUrl string
}

func NewProviderMicrosoft(
	config *Configuration,
	reg Dependencies,
) Provider {
	return &ProviderMicrosoft{
		ProviderGenericOIDC: &ProviderGenericOIDC{
			config: config,
			reg:    reg,
		},
		JWKSUrl: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
	}
}

func (m *ProviderMicrosoft) OAuth2(ctx context.Context) (*oauth2.Config, error) {
	if len(strings.TrimSpace(m.config.Tenant)) == 0 {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("No Tenant specified for the `microsoft` oidc provider %s", m.config.ID))
	}

	endpointPrefix := "https://login.microsoftonline.com/" + m.config.Tenant
	endpoint := oauth2.Endpoint{
		AuthURL:  endpointPrefix + "/oauth2/v2.0/authorize",
		TokenURL: endpointPrefix + "/oauth2/v2.0/token",
	}

	return m.oauth2ConfigFromEndpoint(ctx, endpoint), nil
}

func (m *ProviderMicrosoft) Claims(ctx context.Context, exchange *oauth2.Token, query url.Values) (*Claims, error) {
	raw, ok := exchange.Extra("id_token").(string)
	if !ok || len(raw) == 0 {
		return nil, errors.WithStack(ErrIDTokenMissing)
	}

	parser := new(jwt.Parser)
	unverifiedClaims := microsoftUnverifiedClaims{}
	if _, _, err := parser.ParseUnverified(raw, &unverifiedClaims); err != nil {
		return nil, err
	}

	if _, err := uuid.FromString(unverifiedClaims.TenantID); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("TenantID claim is not a valid UUID: %s", err))
	}

	issuer := "https://login.microsoftonline.com/" + unverifiedClaims.TenantID + "/v2.0"
	ctx = context.WithValue(ctx, oauth2.HTTPClient, m.reg.HTTPClient(ctx).HTTPClient)
	p, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to initialize OpenID Connect Provider: %s", err))
	}

	claims, err := m.verifyAndDecodeClaimsWithProvider(ctx, p, raw)
	if err != nil {
		return nil, err
	}

	return m.updateSubject(ctx, claims, exchange)
}

func (m *ProviderMicrosoft) updateSubject(ctx context.Context, claims *Claims, exchange *oauth2.Token) (*Claims, error) {
	if m.config.SubjectSource == "me" {
		o, err := m.OAuth2(ctx)
		if err != nil {
			return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
		}

		ctx, client := httpx.SetOAuth2(ctx, m.reg.HTTPClient(ctx), o, exchange)
		req, err := retryablehttp.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/me", nil)
		if err != nil {
			return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to fetch from `https://graph.microsoft.com/v1.0/me`: %s", err))
		}
		defer resp.Body.Close()

		if err := logUpstreamError(m.reg.Logger(), resp); err != nil {
			return nil, err
		}

		var user struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to decode JSON from `https://graph.microsoft.com/v1.0/me`: %s", err))
		}

		claims.Subject = user.ID
	}

	return claims, nil
}

type microsoftUnverifiedClaims struct {
	TenantID string `json:"tid,omitempty"`
}

func (c *microsoftUnverifiedClaims) Valid() error {
	return nil
}

func (p *ProviderMicrosoft) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	keySet := gooidc.NewRemoteKeySet(ctx, p.JWKSUrl)
	ctx = gooidc.ClientContext(ctx, p.reg.HTTPClient(ctx).HTTPClient)
	issuer, err := p.extractIssuerFromIDToken(rawIDToken)
	if err != nil {
		return nil, err
	}

	return verifyToken(ctx, keySet, p.config, rawIDToken, issuer)
}

func (p *ProviderMicrosoft) extractIssuerFromIDToken(rawIDToken string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(rawIDToken, jwt.MapClaims{})
	if err != nil {
		return "", errors.WithStack(herodot.ErrInternalServerError.WithReasonf("error decoding: %s", err))
	}

	var kid string
	var claimsIssuer string

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if iss, ok := claims["iss"].(string); ok {
			claimsIssuer = iss
		} else {
			claimsIssuer = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", p.config.Tenant)
		}
		if k, ok := claims["kid"].(string); ok {
			kid = k
		} else {
			return claimsIssuer, nil
		}
	}
	fmt.Println(kid)
	issuer, err := fetchIssuerFromKid(kid)
	if err != nil {
		return claimsIssuer, nil
	}

	return issuer, nil
}

func fetchIssuerFromKid(targetKid string) (string, error) {
	url := "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	jwks, err := fetchMicrosoftDiscoveryKeys(url)
	if err != nil {
		return "", err
	}

	key, err := findKeyByKid(jwks, targetKid)
	if err != nil {
		return "", err
	}

	return key.Iss, nil
}

type JWK struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Alg string   `json:"alg,omitempty"`
	X5t string   `json:"x5t,omitempty"`
	N   string   `json:"n,omitempty"`
	E   string   `json:"e,omitempty"`
	X5c []string `json:"x5c,omitempty"`
	Iss string   `json:"issuer,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func fetchMicrosoftDiscoveryKeys(url string) (*JWKS, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("faield to fetch JWKS: %s", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("unexpected HTTP status: %s", resp.Status))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("failed to read JWKS body: %s", err))
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("failed to umarshal: %s", err))
	}

	return &jwks, nil
}

func findKeyByKid(jwks *JWKS, kid string) (*JWK, error) {
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return &key, nil
		}
	}
	return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("key with kid %s not found", kid))
}
