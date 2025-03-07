// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import (
	"io/fs"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/version"
)

func TestVersion(t *testing.T) {
	t.Run("version is taken from the package version file", func(t *testing.T) {
		pkgVerFile, err := version.GetAgentPackageVersionFilePath()
		require.NoError(t, err)
		t.Cleanup(func() { os.Remove(pkgVerFile) })
		expectedVersion := "1.2.3-test"
		err = os.WriteFile(pkgVerFile, []byte(expectedVersion), 0o644)
		require.NoError(t, err)
		err = version.InitVersionInformation()
		require.NoError(t, err)
		actualVersion := Version()
		assert.Equal(t, expectedVersion, actualVersion)
	})

	t.Run("version removes extra spaces", func(t *testing.T) {
		pkgVerFile, err := version.GetAgentPackageVersionFilePath()
		require.NoError(t, err)
		t.Cleanup(func() { os.Remove(pkgVerFile) })
		expectedVersion := "1.2.3-test"
		expectedVersionXtra := "\t   \n \r\n" + expectedVersion + "   \t \n\n\n\r\n"
		err = os.WriteFile(pkgVerFile, []byte(expectedVersionXtra), 0o644)
		require.NoError(t, err)
		err = version.InitVersionInformation()
		require.NoError(t, err)
		actualVersion := Version()
		assert.Equal(t, expectedVersion, actualVersion)
	})

	t.Run("version fallbacks to beats version if the pkg version file is not readable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("write-only permission are not supported on windows")
		}
		pkgVerFile, err := version.GetAgentPackageVersionFilePath()
		require.NoError(t, err)
		t.Cleanup(func() { os.Remove(pkgVerFile) })
		expectedVersion := version.GetDefaultVersion()
		err = os.WriteFile(pkgVerFile, []byte("1.2.3-test"), 0o200)
		require.NoError(t, err)
		err = version.InitVersionInformation()
		assert.Error(t, err)
		actualVersion := Version()
		assert.Equal(t, expectedVersion, actualVersion)
	})

	t.Run("version fallbacks to beats version if the pkg version file is not there", func(t *testing.T) {
		pkgVerFile, err := version.GetAgentPackageVersionFilePath()
		require.NoError(t, err)
		_, err = os.Stat(pkgVerFile)
		require.ErrorIs(t, err, fs.ErrNotExist)
		err = version.InitVersionInformation()
		assert.Error(t, err)
		expectedVersion := version.GetDefaultVersion()
		actualVersion := Version()
		assert.Equal(t, expectedVersion, actualVersion)
	})
}

func Test_VersionInfo_WithFIPS(t *testing.T) {
	info := Info()
	info.FIPS = false
	assert.NotContains(t, info.String(), "fips:", "found fips indicator")
	info.FIPS = true
	assert.Contains(t, info.String(), "fips: true", "did not find fips indicator")
}

func TestFIPS(t *testing.T) {
	oldFips := fips
	t.Cleanup(func() {
		fips = oldFips
	})

	fips = ""
	assert.False(t, FIPS(), "expected FIPS indicator to be false")
	fips = "false"
	assert.False(t, FIPS(), "expected FIPS indicator to be false")
	fips = "true"
	assert.True(t, FIPS(), "expected FIPS indicator to be true")
}
