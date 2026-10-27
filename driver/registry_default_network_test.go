// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// ABOUTME: Tests that registry Init takes the network ID from config and refuses to start on any doubt.

package driver_test

import (
	"context"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/x/configx"
	"github.com/ory/x/dbal"
	"github.com/ory/x/networkx"
	"github.com/ory/x/servicelocatorx"
	"github.com/ory/x/sqlcon/dockertest"
)

func TestInitNetworkFromConfig(t *testing.T) {
	t.Run("db=sqlite", func(t *testing.T) {
		testInitNetworkFromConfig(t, dbal.NewSQLiteTestDatabase(t))
	})

	t.Run("db=cockroach", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping testing in short mode")
		}
		testInitNetworkFromConfig(t, dockertest.RunTestCockroachDBWithVersion(t, "latest-v23.1"))
	})
}

func newRegistry(ctx context.Context, values map[string]interface{}, dOpts ...driver.RegistryOption) (driver.Registry, error) {
	return driver.New(ctx, os.Stderr, servicelocatorx.NewOptions(), dOpts,
		[]configx.OptionModifier{configx.WithValues(values), configx.SkipValidation()})
}

func countNetworks(t *testing.T, c *pop.Connection) int {
	n, err := c.Count(&networkx.Network{})
	require.NoError(t, err)
	return n
}

func testInitNetworkFromConfig(t *testing.T, dsn string) {
	ctx := context.Background()

	migrator, err := newRegistry(ctx, map[string]interface{}{config.ViperKeyDSN: dsn}, driver.SkipNetworkInit)
	require.NoError(t, err, "network init that is skipped, as migrate does, needs no network key")
	require.NoError(t, migrator.Persister().MigrateUp(ctx))
	conn := migrator.Persister().GetConnection(ctx)

	older := networkx.Network{ID: uuid.Must(uuid.NewV4()), CreatedAt: time.Now().Add(-time.Hour)}
	newer := networkx.Network{ID: uuid.Must(uuid.NewV4()), CreatedAt: time.Now()}
	require.NoError(t, conn.Create(&older))
	require.NoError(t, conn.Create(&newer))

	for _, tc := range []struct {
		name     string
		values   map[string]interface{}
		errorHas string
	}{
		{name: "key missing", values: map[string]interface{}{}, errorHas: config.ViperKeyNetworkID},
		{name: "key not a UUID", values: map[string]interface{}{config.ViperKeyNetworkID: "not-a-uuid"}, errorHas: "not-a-uuid"},
		{name: "key is the nil UUID", values: map[string]interface{}{config.ViperKeyNetworkID: uuid.Nil.String()}, errorHas: config.ViperKeyNetworkID},
		{name: "key names no row", values: map[string]interface{}{config.ViperKeyNetworkID: uuid.Must(uuid.NewV4()).String()}, errorHas: "networks"},
		{
			name: "key equals the forbidden key",
			values: map[string]interface{}{
				config.ViperKeyNetworkID:          newer.ID.String(),
				config.ViperKeyForbiddenNetworkID: newer.ID.String(),
			},
			errorHas: config.ViperKeyForbiddenNetworkID,
		},
		{
			name: "forbidden key not a UUID",
			values: map[string]interface{}{
				config.ViperKeyNetworkID:          newer.ID.String(),
				config.ViperKeyForbiddenNetworkID: "classic",
			},
			errorHas: "classic",
		},
		{
			name: "forbidden key is the nil UUID",
			values: map[string]interface{}{
				config.ViperKeyNetworkID:          newer.ID.String(),
				config.ViperKeyForbiddenNetworkID: uuid.Nil.String(),
			},
			errorHas: config.ViperKeyForbiddenNetworkID,
		},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			before := countNetworks(t, conn)
			tc.values[config.ViperKeyDSN] = dsn

			start := time.Now()
			_, err := newRegistry(ctx, tc.values)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errorHas)
			assert.Less(t, time.Since(start), 30*time.Second, "a config error must not wait for the database retry")
			assert.Equal(t, before, countNetworks(t, conn), "a refused start must not create a network")
		})
	}

	for _, tc := range []struct {
		name   string
		values map[string]interface{}
	}{
		{name: "valid key", values: map[string]interface{}{config.ViperKeyNetworkID: newer.ID.String()}},
		{name: "valid key and other forbidden key", values: map[string]interface{}{
			config.ViperKeyNetworkID:          newer.ID.String(),
			config.ViperKeyForbiddenNetworkID: older.ID.String(),
		}},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			tc.values[config.ViperKeyDSN] = dsn
			tc.values[config.ViperKeyIdentitySchemas] = config.Schemas{{
				ID:  config.DefaultIdentityTraitsSchemaID,
				URL: "base64://" + base64.StdEncoding.EncodeToString([]byte(`{"type":"object","properties":{"traits":{"type":"object"}}}`)),
			}}

			reg, err := newRegistry(ctx, tc.values)
			require.NoError(t, err)
			assert.Equal(t, newer.ID, reg.Persister().NetworkID(ctx), "config must win over the oldest network row")

			i := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
			require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(ctx, i))
			var stored identity.Identity
			require.NoError(t, conn.Where("id = ?", i.ID).First(&stored))
			assert.Equal(t, newer.ID, stored.NID)
		})
	}
}
