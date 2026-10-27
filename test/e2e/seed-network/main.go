// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// ABOUTME: Inserts the networks row that NETWORK_ID names into the database that DSN names, so e2e Kratos can start.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"

	"github.com/ory/kratos/driver"
	"github.com/ory/x/configx"
	"github.com/ory/x/dbal"
	"github.com/ory/x/networkx"
	"github.com/ory/x/servicelocatorx"
)

func init() {
	dbal.RegisterDriver(func() dbal.Driver {
		return driver.NewRegistryDefault()
	})
}

func seedNetwork(c *pop.Connection, nid uuid.UUID) error {
	exists, err := c.Where("id = ?", nid).Exists(&networkx.Network{})
	if err != nil || exists {
		return err
	}
	return c.Create(&networkx.Network{ID: nid})
}

func main() {
	ctx := context.Background()
	nid, err := uuid.FromString(os.Getenv("NETWORK_ID"))
	if err != nil || nid == uuid.Nil {
		fmt.Fprintf(os.Stderr, "NETWORK_ID must be a UUID that is not nil, got %q\n", os.Getenv("NETWORK_ID"))
		os.Exit(1)
	}

	reg, err := driver.New(ctx, os.Stderr, servicelocatorx.NewOptions(), []driver.RegistryOption{driver.SkipNetworkInit},
		[]configx.OptionModifier{configx.SkipValidation()})
	if err != nil {
		os.Exit(1)
	}
	if err := seedNetwork(reg.Persister().GetConnection(ctx), nid); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to seed network %s: %v\n", nid, err)
		os.Exit(1)
	}
	fmt.Printf("Network %s is in table networks.\n", nid)
}
