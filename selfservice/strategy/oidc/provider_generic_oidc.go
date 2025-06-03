// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/ory/herodot"
	"github.com/ory/x/stringslice"
)

var _ Provider = new(ProviderGenericOIDC)

type ProviderGenericOIDC struct {
	p      *gooidc.Provider
	config *Configuration
	reg    Dependencies
}

func NewProviderGenericOIDC(
	config *Configuration,
	reg Dependencies,
) Provider {
	return &ProviderGenericOIDC{
		config: config,
		reg:    reg,
	}
}

const (
	ClaimsSourceIDToken  = "id_token"
	ClaimsSourceUserInfo = "userinfo"
)

func (g *ProviderGenericOIDC) Config() *Configuration {
	return g.config
}

func (g *ProviderGenericOIDC) withHTTPClientContext(ctx context.Context) context.Context {
	return gooidc.ClientContext(ctx, g.reg.HTTPClient(ctx).HTTPClient)
}

func (g *ProviderGenericOIDC) provider(ctx context.Context) (*gooidc.Provider, error) {
	if g.p == nil {
		p, err := gooidc.NewProvider(g.withHTTPClientContext(ctx), g.config.IssuerURL)
		if err != nil {
			return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to initialize OpenID Connect Provider: %s", err))
		}
		g.p = p
	}
	return g.p, nil
}

func (g *ProviderGenericOIDC) oauth2ConfigFromEndpoint(ctx context.Context, endpoint oauth2.Endpoint) *oauth2.Config {
	scope := g.config.Scope
	if !stringslice.Has(scope, gooidc.ScopeOpenID) {
		scope = append(scope, gooidc.ScopeOpenID)
	}

	return &oauth2.Config{
		ClientID:     g.config.ClientID,
		ClientSecret: g.config.ClientSecret,
		Endpoint:     endpoint,
		Scopes:       scope,
		RedirectURL:  g.config.Redir(g.reg.Config().OIDCRedirectURIBase(ctx)),
	}
}

func (g *ProviderGenericOIDC) OAuth2(ctx context.Context) (*oauth2.Config, error) {
	p, err := g.provider(ctx)
	if err != nil {
		return nil, err
	}

	endpoint := p.Endpoint()
	return g.oauth2ConfigFromEndpoint(ctx, endpoint), nil
}

func (g *ProviderGenericOIDC) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	var options []oauth2.AuthCodeOption

	if isForced(r) {
		options = append(options, oauth2.SetAuthURLParam("prompt", "login"))
	}
	if len(g.config.RequestedClaims) != 0 {
		options = append(options, oauth2.SetAuthURLParam("claims", string(g.config.RequestedClaims)))
	}

	return options
}

func (g *ProviderGenericOIDC) verifyAndDecodeClaimsWithProvider(ctx context.Context, provider *gooidc.Provider, raw string) (*Claims, error) {
	token, err := provider.VerifierContext(g.withHTTPClientContext(ctx), &gooidc.Config{ClientID: g.config.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}

	var claims Claims
	if err := token.Claims(&claims); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}

	var rawClaims map[string]interface{}
	if err := token.Claims(&rawClaims); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}
	claims.RawClaims = rawClaims

	return &claims, nil
}

func (g *ProviderGenericOIDC) Claims(ctx context.Context, exchange *oauth2.Token, _ url.Values) (*Claims, error) {
	switch g.config.ClaimsSource {
	case ClaimsSourceIDToken, "":
		return g.claimsFromIDToken(ctx, exchange)
	case ClaimsSourceUserInfo:
		return g.claimsFromUserInfo(ctx, exchange)
	}

	return nil, errors.WithStack(herodot.ErrInternalServerError.
		WithReasonf("Unknown claims source: %q", g.config.ClaimsSource))
}

func (g *ProviderGenericOIDC) claimsFromUserInfo(ctx context.Context, exchange *oauth2.Token) (*Claims, error) {
	p, err := g.provider(ctx)
	if err != nil {
		return nil, err
	}

	userInfo, err := p.UserInfo(g.withHTTPClientContext(ctx), oauth2.StaticTokenSource(exchange))
	if err != nil {
		return nil, err
	}

	var claims Claims
	if err = userInfo.Claims(&claims); err != nil {
		return nil, err
	}
	var rawClaims map[string]interface{}
	if err := userInfo.Claims(&rawClaims); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}
	claims.RawClaims = rawClaims

	// NOTE: Due to the possibility of token substitution attacks (see Section
	// 16.11), the UserInfo Response is not guaranteed to be about the End-User
	// identified by the sub (subject) element of the ID Token. The sub Claim in the
	// UserInfo Response MUST be verified to exactly match the sub Claim in the ID
	// Token; if they do not match, the UserInfo Response values MUST NOT be used.
	// See https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	idToken, err := g.verifiedIDToken(ctx, exchange)
	if err != nil {
		return nil, err
	}

	if idToken.Subject != claims.Subject {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReason("sub (Subject) claim mismatch between ID token and UserInfo endpoint"))
	}

	// If signed, the UserInfo Response MUST contain the Claims iss (issuer) and aud
	// (audience) as members. The iss value MUST be the OP's Issuer Identifier URL.
	// The aud value MUST be or include the RP's Client ID value.
	// See https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	//
	// Consequently, the issuer might not be present in the UserInfo response and we
	// need to set it here.
	if claims.Issuer == "" {
		claims.Issuer = idToken.Issuer
	}

	return &claims, nil
}

func (g *ProviderGenericOIDC) claimsFromIDToken(ctx context.Context, exchange *oauth2.Token) (*Claims, error) {
	p, raw, err := g.idTokenAndProvider(ctx, exchange)
	if err != nil {
		return nil, err
	}

	return g.verifyAndDecodeClaimsWithProvider(ctx, p, raw)
}

func (g *ProviderGenericOIDC) idTokenAndProvider(ctx context.Context, exchange *oauth2.Token) (*gooidc.Provider, string, error) {
	raw, ok := exchange.Extra("id_token").(string)
	if !ok || len(raw) == 0 {
		return nil, "", errors.WithStack(ErrIDTokenMissing)
	}

	p, err := g.provider(ctx)
	if err != nil {
		return nil, "", err
	}

	return p, raw, nil
}

func (g *ProviderGenericOIDC) verifiedIDToken(ctx context.Context, exchange *oauth2.Token) (*gooidc.IDToken, error) {
	p, raw, err := g.idTokenAndProvider(ctx, exchange)
	if err != nil {
		return nil, err
	}

	token, err := p.VerifierContext(g.withHTTPClientContext(ctx), &gooidc.Config{ClientID: g.config.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}

	return token, nil
}

func (g *ProviderGenericOIDC) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	if !g.config.IDTokenVerificationEnabled {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("The provider %s does not support id_token verification", g.Config().ID))
	}
	p, err := g.provider(ctx)
	if err != nil {
		return nil, err
	}
	// Boxyhq use camelCase for keys in claims, but Kratos expect the keys to be snake_case.
	// Fortunately, the verifyAndDecodeClaimsWithProvider will put the whole Boxyhq claims into the "raw_claims" field.
	// So we can get Boxyhq claims from raw_claims, and extract fields like "firstName" and "lastName".
	claims, err := g.verifyAndDecodeClaimsWithProvider(ctx, p, rawIDToken)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

type OpenIDConfiguration struct {
	Issuer  string `json:"issuer"`
	JWKSUrl string `json:"jwks_uri"`
}

func fetchOpenIdConfiguration(url string) (*OpenIDConfiguration, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("faield to fetch OpenIDConfiguration: %s", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("unexpected HTTP status: %s", resp.Status))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("failed to read OpenIDConfiguration body: %s", err))
	}

	var openIDConfiguration OpenIDConfiguration
	if err := json.Unmarshal(body, &openIDConfiguration); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("failed to umarshal: %s", err))
	}

	return &openIDConfiguration, nil
}
