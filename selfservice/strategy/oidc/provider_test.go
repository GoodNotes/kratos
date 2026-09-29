// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/herodot"
)

func TestClaimsValidate(t *testing.T) {
	require.Error(t, new(Claims).Validate())
	require.Error(t, (&Claims{Issuer: "not-empty"}).Validate())
	require.Error(t, (&Claims{Issuer: "not-empty"}).Validate())
	require.Error(t, (&Claims{Subject: "not-empty"}).Validate())
	require.Error(t, (&Claims{Subject: "not-empty"}).Validate())
	require.NoError(t, (&Claims{Issuer: "not-empty", Subject: "not-empty"}).Validate())
}

type TestProvider struct {
	*ProviderGenericOIDC
}

func NewTestProvider(c *Configuration, reg Dependencies) Provider {
	return &TestProvider{
		ProviderGenericOIDC: NewProviderGenericOIDC(c, reg).(*ProviderGenericOIDC),
	}
}

func RegisterTestProvider(t *testing.T, id string) {
	supportedProviders[id] = func(c *Configuration, reg Dependencies) Provider {
		return NewTestProvider(c, reg)
	}
	t.Cleanup(func() {
		delete(supportedProviders, id)
	})
}

var _ IDTokenVerifier = new(TestProvider)

func (t *TestProvider) Verify(_ context.Context, token string) (*Claims, error) {
	if token == "error" {
		return nil, fmt.Errorf("stub error")
	}
	if token == "bad-request" {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReason("stub bad request"))
	}
	c := Claims{}
	if err := json.Unmarshal([]byte(token), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func TestProcessIDTokenVerifyErrors(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	s := new(Strategy)

	t.Run("case=keeps a client error from the verifier", func(t *testing.T) {
		_, err := s.processIDToken(r, new(TestProvider), "bad-request", "")
		var herr *herodot.DefaultError
		require.ErrorAs(t, err, &herr)
		assert.Equal(t, http.StatusBadRequest, herr.StatusCode())
		assert.Equal(t, "stub bad request", herr.Reason())
	})

	t.Run("case=wraps any other verifier error as a server error", func(t *testing.T) {
		_, err := s.processIDToken(r, new(TestProvider), "error", "")
		var herr *herodot.DefaultError
		require.ErrorAs(t, err, &herr)
		assert.Equal(t, http.StatusInternalServerError, herr.StatusCode())
		assert.Equal(t, "Could not verify id_token", herr.Reason())
	})
}

func TestLocale(t *testing.T) {
	// test json unmarshal
	for _, tc := range []struct {
		name      string
		json      string
		expected  string
		assertErr assert.ErrorAssertionFunc
	}{{
		name:     "empty",
		json:     `{}`,
		expected: "",
	}, {
		name:     "empty string locale",
		json:     `{"locale":""}`,
		expected: "",
	}, {
		name:      "invalid string locale",
		json:      `{"locale":"""}`,
		assertErr: assert.Error,
	}, {
		name:     "string locale",
		json:     `{"locale":"en-US"}`,
		expected: "en-US",
	}, {
		name:     "linkedin locale",
		json:     `{"locale":{"country":"US","language":"en","ignore":"me"}}`,
		expected: "en-US",
	}, {
		name:     "missing country linkedin locale",
		json:     `{"locale":{"language":"en"}}`,
		expected: "en",
	}, {
		name:     "missing language linkedin locale",
		json:     `{"locale":{"country":"US"}}`,
		expected: "US",
	}, {
		name:     "invalid linkedin locale",
		json:     `{"locale":{"invalid":"me"}}`,
		expected: "",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			var c Claims
			err := json.Unmarshal([]byte(tc.json), &c)
			if tc.assertErr != nil {
				tc.assertErr(t, err)
				return
			}
			require.NoError(t, err)
			assert.EqualValues(t, tc.expected, c.Locale)
		})
	}
}
