// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package snapshot

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/pkg/version"
)

func TestNonDefaultSourceURI(t *testing.T) {
	version, err := version.ParseVersion("8.12.0-SNAPSHOT")
	require.NoError(t, err)

	config := artifact.Config{
		SourceURI: "localhost:1234",
	}
	sourceURI, err := snapshotURI(version, &config)
	require.NoError(t, err)
	require.Equal(t, config.SourceURI, sourceURI)

}
