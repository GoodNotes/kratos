// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/identity"
	"github.com/ory/x/sqlxx"
)

// fakeInternalContexter is a minimal InternalContexter for testing
// SetDuplicateCredentials/DuplicateCredentials without a full flow type.
type fakeInternalContexter struct {
	ctx sqlxx.JSONRawMessage
}

func (f *fakeInternalContexter) EnsureInternalContext() {
	if len(f.ctx) == 0 {
		f.ctx = sqlxx.JSONRawMessage(`{}`)
	}
}

func (f *fakeInternalContexter) GetInternalContext() sqlxx.JSONRawMessage {
	return f.ctx
}

func (f *fakeInternalContexter) SetInternalContext(ctx sqlxx.JSONRawMessage) {
	f.ctx = ctx
}

func TestDuplicateCredentialsRoundTrip(t *testing.T) {
	t.Run("case=no duplicate credentials set", func(t *testing.T) {
		f := &fakeInternalContexter{}
		dc, err := DuplicateCredentials(f)
		require.NoError(t, err)
		assert.Nil(t, dc)
	})

	t.Run("case=round-trips available credential types and providers", func(t *testing.T) {
		f := &fakeInternalContexter{}
		in := DuplicateCredentialsData{
			CredentialsType:          identity.CredentialsTypeOIDC,
			CredentialsConfig:        sqlxx.JSONRawMessage(`{"foo":"bar"}`),
			DuplicateIdentifier:      "duplicate@ory.sh",
			AvailableCredentialTypes: []string{"password", "oidc"},
			AvailableProviders:       []string{"google", "microsoft"},
		}
		require.NoError(t, SetDuplicateCredentials(f, in))

		out, err := DuplicateCredentials(f)
		require.NoError(t, err)
		require.NotNil(t, out)
		assert.Equal(t, in.CredentialsType, out.CredentialsType)
		assert.Equal(t, in.DuplicateIdentifier, out.DuplicateIdentifier)
		assert.Equal(t, in.AvailableCredentialTypes, out.AvailableCredentialTypes)
		assert.Equal(t, in.AvailableProviders, out.AvailableProviders)
	})

	t.Run("case=older flows without the new fields decode with empty slices", func(t *testing.T) {
		// Simulates data persisted before AvailableCredentialTypes/AvailableProviders existed.
		f := &fakeInternalContexter{}
		in := DuplicateCredentialsData{
			CredentialsType:     identity.CredentialsTypeOIDC,
			DuplicateIdentifier: "legacy@ory.sh",
		}
		require.NoError(t, SetDuplicateCredentials(f, in))

		out, err := DuplicateCredentials(f)
		require.NoError(t, err)
		require.NotNil(t, out)
		assert.Equal(t, "legacy@ory.sh", out.DuplicateIdentifier)
		assert.Empty(t, out.AvailableCredentialTypes)
		assert.Empty(t, out.AvailableProviders)
	})

	t.Run("case=malformed internal context returns an error", func(t *testing.T) {
		f := &fakeInternalContexter{ctx: sqlxx.JSONRawMessage(`{"registration_duplicate_credentials":{"CredentialsType":123}}`)}
		dc, err := DuplicateCredentials(f)
		assert.Error(t, err)
		assert.NotNil(t, dc)
	})
}
