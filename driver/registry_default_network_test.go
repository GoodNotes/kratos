// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// ABOUTME: Tests that registry Init takes the network ID from config and refuses to start on any doubt.

package driver_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
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
	t.Run("config errors refuse before the database retry", testConfigErrorsRefuseBeforeRetry)

	t.Run("db=sqlite", func(t *testing.T) {
		testInitNetworkFromConfig(t, "sqlite://"+filepath.Join(t.TempDir(), "db.sqlite")+"?_fk=true&mode=rwc")
	})

	t.Run("db=cockroach", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping testing in short mode")
		}
		testInitNetworkFromConfig(t, dockertest.RunTestCockroachDBWithVersion(t, "latest-v23.1"))
	})

	t.Run("db=memory", func(t *testing.T) {
		ctx := context.Background()
		nid := uuid.Must(uuid.NewV4())

		reg, err := newRegistry(ctx, map[string]interface{}{
			config.ViperKeyDSN:       dbal.NewSQLiteTestDatabase(t),
			config.ViperKeyNetworkID: nid.String(),
		})
		require.NoError(t, err, "a memory database lives only in this process, so nothing else can seed its network")
		assert.Equal(t, nid, reg.Persister().NetworkID(ctx))

		n, err := reg.Persister().(interface {
			NetworkByID(context.Context, uuid.UUID) (*networkx.Network, error)
		}).NetworkByID(ctx, nid)
		require.NoError(t, err)
		assert.Equal(t, nid, n.ID)
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

func testConfigErrorsRefuseBeforeRetry(t *testing.T) {
	ctx := context.Background()
	// Nothing listens on port 1, so any database call would retry for minutes.
	unreachable := "postgres://kratos:secret@127.0.0.1:1/kratos?sslmode=disable"
	valid := uuid.Must(uuid.NewV4()).String()

	for _, tc := range []struct {
		name   string
		values map[string]interface{}
		error  string
	}{
		{
			name:   "key missing",
			values: map[string]interface{}{},
			error:  `required config value "network.id" was not set`,
		},
		{
			name:   "key not a UUID",
			values: map[string]interface{}{config.ViperKeyNetworkID: "not-a-uuid"},
			error:  `config value "network.id" is not a UUID: "not-a-uuid"`,
		},
		{
			name:   "key is the nil UUID",
			values: map[string]interface{}{config.ViperKeyNetworkID: uuid.Nil.String()},
			error:  `config value "network.id" must not be the nil UUID`,
		},
		{
			name:   "key equals the forbidden key",
			values: map[string]interface{}{config.ViperKeyNetworkID: valid, config.ViperKeyForbiddenNetworkID: valid},
			error:  `config value "network.id" equals config value "network.forbidden_id": this release must not use network ` + valid,
		},
		{
			name:   "forbidden key not a UUID",
			values: map[string]interface{}{config.ViperKeyNetworkID: valid, config.ViperKeyForbiddenNetworkID: "classic"},
			error:  `config value "network.forbidden_id" is not a UUID: "classic"`,
		},
		{
			name:   "forbidden key is the nil UUID",
			values: map[string]interface{}{config.ViperKeyNetworkID: valid, config.ViperKeyForbiddenNetworkID: uuid.Nil.String()},
			error:  `config value "network.forbidden_id" must not be the nil UUID`,
		},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			tc.values[config.ViperKeyDSN] = unreachable

			start := time.Now()
			_, err := newRegistry(ctx, tc.values)
			require.Error(t, err)
			assert.Equal(t, tc.error, err.Error())
			assert.Less(t, time.Since(start), 10*time.Second, "a config error must not wait for the database retry")
		})
	}
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

	t.Run("case=key names no row", func(t *testing.T) {
		before := countNetworks(t, conn)
		unknown := uuid.Must(uuid.NewV4())

		start := time.Now()
		_, err := newRegistry(ctx, map[string]interface{}{config.ViperKeyDSN: dsn, config.ViperKeyNetworkID: unknown.String()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `config value "network.id" names network `+unknown.String()+", which is not in table networks")
		assert.Less(t, time.Since(start), 30*time.Second, "a missing row must not wait for the database retry")
		assert.Equal(t, before, countNetworks(t, conn), "a refused start must not create a network")
	})

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
