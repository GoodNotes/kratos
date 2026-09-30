// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
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

	return m.applyObjectIDSubject(claims)
}

func (m *ProviderMicrosoft) applyObjectIDSubject(claims *Claims) (*Claims, error) {
	if m.config.SubjectSource != "oid" {
		return claims, nil
	}

	// Fail with a scope hint instead of the generic empty-subject error.
	if claims.Object == "" {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReason("The Microsoft ID token has no `oid` claim, which `subject_source: oid` requires. Request the `profile` scope."))
	}

	claims.Subject = claims.Object
	return claims, nil
}

type microsoftUnverifiedClaims struct {
	TenantID string `json:"tid,omitempty"`
}

func (c *microsoftUnverifiedClaims) Valid() error {
	return nil
}

func (p *ProviderMicrosoft) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	unverifiedClaims := microsoftUnverifiedClaims{}
	if _, _, err := new(jwt.Parser).ParseUnverified(rawIDToken, &unverifiedClaims); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("Unable to decode the Microsoft ID token: %s", err))
	}

	tenantID, err := uuid.FromString(unverifiedClaims.TenantID)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("TenantID claim is not a valid UUID: %s", err))
	}

	// Only a tenant configured as a UUID can be pinned; common, organizations, consumers and domain names accept any tenant.
	if configured, err := uuid.FromString(p.config.Tenant); err == nil && configured != tenantID {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("The Microsoft ID token claims tenant %s, which provider %s does not accept.", tenantID, p.config.ID))
	}

	ctx = gooidc.ClientContext(ctx, p.reg.HTTPClient(ctx).HTTPClient)
	keySet := gooidc.NewRemoteKeySet(ctx, p.JWKSUrl)
	claims, err := verifyToken(ctx, keySet, p.config, rawIDToken, "https://login.microsoftonline.com/"+tenantID.String()+"/v2.0")
	if err != nil {
		return nil, err
	}

	return p.applyObjectIDSubject(claims)
}
