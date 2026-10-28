// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package driver_test

import (
	"context"
	"os"
	"testing"

	"github.com/ory/x/servicelocatorx"

	"github.com/gofrs/uuid"

	"github.com/ory/x/configx"
	"github.com/ory/x/dbal"
	"github.com/ory/x/networkx"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
)

func TestDriverNew(t *testing.T) {
	ctx := context.Background()
	dsn := dbal.NewSQLiteTestDatabase(t)
	nid := uuid.Must(uuid.NewV4())

	migrator, err := driver.New(ctx, os.Stderr, servicelocatorx.NewOptions(), []driver.RegistryOption{driver.SkipNetworkInit},
		[]configx.OptionModifier{configx.WithValue(config.ViperKeyDSN, dsn), configx.SkipValidation()})
	require.NoError(t, err)
	require.NoError(t, migrator.Persister().MigrateUp(ctx))
	require.NoError(t, migrator.Persister().GetConnection(ctx).Create(&networkx.Network{ID: nid}))

	r, err := driver.New(
		context.Background(),
		os.Stderr,
		servicelocatorx.NewOptions(),
		nil,
		[]configx.OptionModifier{
			configx.WithValue(config.ViperKeyDSN, dsn),
			configx.WithValue(config.ViperKeyNetworkID, nid.String()),
			configx.SkipValidation(),
		})
	require.NoError(t, err)

	assert.EqualValues(t, dsn, r.Config().DSN(ctx))
	require.NoError(t, r.Persister().Ping())

	assert.Equal(t, nid, r.Persister().NetworkID(context.Background()))

	n, err := r.Persister().DetermineNetwork(context.Background())
	require.NoError(t, err)
	assert.Equal(t, r.Persister().NetworkID(context.Background()), n.ID)
}
