// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"testing"

	"github.com/stretchr/testify/require"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
)

func TestSelectLatestReleaseBefore(t *testing.T) {
	versions := []string{"9.4.0", "9.4.3", "9.5.0", "v9.3.2", "8.19.1", "not-a-version"}
	got, err := selectLatestReleaseBefore(versions, "9.5.0")
	require.NoError(t, err)
	require.Equal(t, "9.4.3", got)
}

func TestInferNextProjectMinorVersion(t *testing.T) {
	parsed, err := devtools.ParseReleaseVersion("9.5.0")
	require.NoError(t, err)
	got := devtools.InferNextProjectMinorVersion(parsed)
	require.Equal(t, "9.6.0", got)
}
