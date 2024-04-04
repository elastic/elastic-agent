// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration && windows

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

func checkPlatformUnprivileged(t *testing.T, f *atesting.Fixture, topPath string) {
	// Check that the elastic-agent user/group exist.
	_, err := install.FindUID(install.ElasticUsername)
	require.NoErrorf(t, err, "failed to find %s user", install.ElasticUsername)
	_, err = install.FindGID(install.ElasticGroupName)
	require.NoError(t, err, "failed to find %s group", install.ElasticGroupName)

	var output atesting.AgentStatusOutput
	require.Eventuallyf(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		output, err = f.ExecStatus(ctx)
		return err == nil
	}, 3*time.Minute, 10*time.Second, "never got the status")

	require.False(t, output.IsZero(), "must have an agent ID")
	require.True(t, output.Info.Unprivileged, "must be unprivileged")
}
