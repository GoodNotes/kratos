// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// ABOUTME: Tests that the e2e seed inserts the configured network once and keeps the row on a rerun.

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/x/configx"
	"github.com/ory/x/networkx"
	"github.com/ory/x/servicelocatorx"
)

func TestSeedNetwork(t *testing.T) {
	ctx := context.Background()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "db.sqlite") + "?_fk=true&mode=rwc"
	reg, err := driver.New(ctx, os.Stderr, servicelocatorx.NewOptions(), []driver.RegistryOption{driver.SkipNetworkInit},
		[]configx.OptionModifier{configx.WithValue(config.ViperKeyDSN, dsn), configx.SkipValidation()})
	require.NoError(t, err)
	require.NoError(t, reg.Persister().MigrateUp(ctx))
	conn := reg.Persister().GetConnection(ctx)
	nid := uuid.Must(uuid.NewV4())

	require.NoError(t, seedNetwork(conn, nid))
	require.NoError(t, seedNetwork(conn, nid), "a rerun of the e2e setup must not fail on the existing row")

	var rows []networkx.Network
	require.NoError(t, conn.All(&rows))
	require.Len(t, rows, 1)
	assert.Equal(t, nid, rows[0].ID)
}
