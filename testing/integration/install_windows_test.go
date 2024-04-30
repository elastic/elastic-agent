// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration && windows

package integration

import (
	"testing"

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
}
