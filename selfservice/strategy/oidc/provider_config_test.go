// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/container"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/selfservice/strategy/oidc"
)

func TestConfig(t *testing.T) {
	ctx := context.Background()
	conf, reg := internal.NewFastRegistryWithMocks(t)

	var c map[string]interface{}
	require.NoError(t, json.NewDecoder(
		bytes.NewBufferString(`{"config":{"providers": [{"provider": "generic"}]}}`)).Decode(&c))
	conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypeOIDC), c)

	s := oidc.NewStrategy(reg)
	collection, err := s.Config(ctx)
	require.NoError(t, err)

	require.Len(t, collection.Providers, 1)
	assert.Equal(t, "generic", collection.Providers[0].Provider)
}

func TestProviderPublicIDResolvesToCanonicalProvider(t *testing.T) {
	var collection oidc.ConfigurationCollection
	require.NoError(t, json.Unmarshal([]byte(`{"providers":[{"id":"google-goodsystems","public_id":"google","provider":"google","client_id":"goodmeet-client"}]}`), &collection))

	provider, err := collection.Provider("google", nil)
	require.NoError(t, err)
	assert.Equal(t, "google-goodsystems", provider.Config().ID)
	assert.Equal(t, "goodmeet-client", provider.Config().ClientID)
}

func TestProviderPublicIDKeepsRegisteredCallback(t *testing.T) {
	provider := oidc.Configuration{ID: "google-goodsystems", PublicID: "google"}
	public, err := url.Parse("https://kratos.goodmeet.test/")
	require.NoError(t, err)

	assert.Equal(t, "https://kratos.goodmeet.test/self-service/methods/oidc/callback/google", provider.Redir(public))
}

func TestProviderPublicIDKeepsBrowserSubmitValue(t *testing.T) {
	ui := container.New("/self-service/login")
	oidc.AddProviders(ui, []oidc.Configuration{{ID: "google-goodsystems", PublicID: "google"}}, text.NewInfoLoginWith)
	raw, err := json.Marshal(ui.Nodes)
	require.NoError(t, err)
	assert.Equal(t, "google", gjson.GetBytes(raw, "0.attributes.value").String())
}

func TestProviderPublicIDRejectsAmbiguousSelection(t *testing.T) {
	for _, providers := range [][]oidc.Configuration{
		{{ID: "google", Provider: "google"}, {ID: "google-goodsystems", PublicID: "google", Provider: "google"}},
		{{ID: "google-goodsystems", PublicID: "google", Provider: "google"}, {ID: "google", Provider: "google"}},
	} {
		_, err := (oidc.ConfigurationCollection{Providers: providers}).Provider("google", nil)
		require.Error(t, err)
	}
}

func TestProviderWithoutPublicIDKeepsExistingBehavior(t *testing.T) {
	for _, id := range []string{"google", "google-goodsystems"} {
		t.Run(id, func(t *testing.T) {
			collection := oidc.ConfigurationCollection{Providers: []oidc.Configuration{{ID: id, Provider: "google", ClientID: "client"}}}
			provider, err := collection.Provider(id, nil)
			require.NoError(t, err)
			assert.Equal(t, id, provider.Config().ID)
			assert.Equal(t, id, provider.Config().RequestID())
			public, err := url.Parse("https://kratos.example.test")
			require.NoError(t, err)
			assert.Equal(t, "https://kratos.example.test/self-service/methods/oidc/callback/"+id, provider.Config().Redir(public))
			if id != "google" {
				_, err = collection.Provider("google", nil)
				require.Error(t, err)
			}
		})
	}
}
