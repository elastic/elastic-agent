// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package diagnostics

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/google/pprof/profile"

	agentclient "github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	agentruntime "github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/version"
)

func TestRedactResults(t *testing.T) {
	exampleConfig := mapstr.M{
		"root": mapstr.M{
			"passphrase": "unredacted",
			"nested1": mapstr.M{
				"certificate": "unredacted",
				"nested2": mapstr.M{
					"passphrase": "unredacted",
					"password":   "unredacted",
					"nested3": mapstr.M{
						"token": "unredacted",
						"key":   "unredacted",
					},
					"ssl": mapstr.M{ // ssh-keygen -f ~/test-key -t rsa -b 4096
						"key": `-----BEGIN OPENSSH PRIVATE KEY----- 
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
-----END OPENSSH PRIVATE KEY-----`,
					},
				},
			},
		},
	}

	formatted, err := yaml.Marshal(exampleConfig)
	require.NoError(t, err)
	errOut := strings.Builder{}
	outWriter := strings.Builder{}
	res := client.DiagnosticFileResult{Content: formatted, ContentType: "application/yaml"}

	err = writeRedacted(&errOut, &outWriter, "test/path", res)
	require.NoError(t, err)

	require.Empty(t, errOut.String())
	require.NotContains(t, outWriter.String(), "unredacted")
	require.NotContains(t, outWriter.String(), "END OPENSSH PRIVATE KEY")
}

func TestRedactComplexKeys(t *testing.T) {
	// taken directly from the yaml spec: https://yaml.org/spec/1.1/#c-mapping-key
	// This test mostly serves to document that part of the YAML library doesn't work properly
	t.Skip("YAML library currently can't do this, come back to see if the library works.")
	testComplexKey := `
sequence:
- one
- two
mapping:
  ? sky 
  : blue
  ? sea : green`

	errOut := strings.Builder{}
	outWriter := strings.Builder{}

	res := client.DiagnosticFileResult{Content: []byte(testComplexKey), ContentType: "application/yaml"}
	err := writeRedacted(&errOut, &outWriter, "test/path", res)
	require.NoError(t, err)

	require.Empty(t, errOut.String())
}

func TestUnitAndStateMapping(t *testing.T) {
	// this structure causes problems due to the compound agentruntime.ComponentUnitKey map key
	exampleState := agentruntime.ComponentState{
		State:   agentclient.UnitStateStarting,
		Message: "test",
		Units: map[agentruntime.ComponentUnitKey]agentruntime.ComponentUnitState{
			{UnitType: agentclient.UnitTypeInput, UnitID: "test-unit"}:    {Message: "test unit"},
			{UnitType: agentclient.UnitTypeOutput, UnitID: "test-unit-2"}: {Message: "test unit 2"},
		},
		VersionInfo: agentruntime.ComponentVersionInfo{Name: "test-component", Version: "0"},
	}

	formatted, err := yaml.Marshal(exampleState)
	require.NoError(t, err)
	t.Logf("%s", formatted)
	errOut := strings.Builder{}
	outWriter := strings.Builder{}
	res := client.DiagnosticFileResult{Content: formatted, ContentType: "application/yaml"}

	err = writeRedacted(&errOut, &outWriter, "test/path", res)
	require.NoError(t, err)

	require.Empty(t, errOut.String())
}

func TestZipLogs(t *testing.T) {
	// Setup a directory structure of: logs/httpjson/log.ndjson
	{
		paths.SetTop(t.TempDir())
		dir := filepath.Join(paths.Home(), "logs/sub-dir")
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "log.ndjson"), []byte(".\n"), 0o600))
	}

	// Zip the logs directory.
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	require.NoError(t, zipLogs(w, time.Now()))
	require.NoError(t, w.Close())

	type zippedItem struct {
		Name  string
		IsDir bool
	}

	// Read back the contents.
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	var observed []zippedItem
	for _, f := range r.File {
		observed = append(observed, zippedItem{Name: f.Name, IsDir: f.FileInfo().IsDir()})
	}

	// Verify the results.
	expected := []zippedItem{
		{"logs/", true},
		{"logs/elastic-agent-unknow/", true},
		{"logs/elastic-agent-unknow/sub-dir/", true},
		{"logs/elastic-agent-unknow/sub-dir/log.ndjson", false},
	}
	assert.Equal(t, expected, observed)
}

func TestGlobalHooks(t *testing.T) {
	testPkgVer := "1.2.3-test"
	setupPkgVersion(t, testPkgVer, 0o644)
	hooks := GlobalHooks()
	assert.NotEmpty(t, hooks, "multiple hooks should be returned")
	deadline, _ := t.Deadline()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(func() { cancel() })
	for _, h := range hooks {
		output := h.Hook(ctx)
		assert.NotEmpty(t, h, "hook should produce output")
		var ok bool
		var err error
		switch h.Name {
		case "version":
			ok, err = isVersion(output)
			assert.Truef(t, ok, "hook %q returned incompatible data: %q", h.Name, hex.EncodeToString(output))
			assert.NoErrorf(t, err, "hook %q validation error: %v", err)
		case "package version":
			assert.Equal(t, testPkgVer, string(output), "hook package version does not match")
		default:
			ok, err = isPprof(output)
			assert.Truef(t, ok, "hook %q returned incompatible data: %q", h.Name, hex.EncodeToString(output))
			assert.NoErrorf(t, err, "hook %q validation error: %v", err)
		}
	}
}

func TestPackageVersionHook(t *testing.T) {
	for _, h := range GlobalHooks() {
		if h.Name == "package version" {
			testPackageVersionHook(t, h)
			return
		}
	}
	t.Fatal("package version hook not returned by GlobalHooks()")
}

func testPackageVersionHook(t *testing.T, pkgVersHook Hook) {
	deadline, _ := t.Deadline()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	t.Run("package version hook returns an error if no package version file is found", func(t *testing.T) {
		output := pkgVersHook.Hook(ctx)
		assert.True(t, strings.HasPrefix(string(output), "error: "))
	})
	t.Run("package version hook returns an error if package version file is not readable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("windows does not support non-readable permissions on files")
		}
		testPkgVer := "1.2.3-test"
		setupPkgVersion(t, testPkgVer, 0o222)
		output := pkgVersHook.Hook(ctx)
		assert.True(t, strings.HasPrefix(string(output), "error: "))
		assert.True(t, strings.HasSuffix(string(output), "permission denied\""))
	})
	t.Run("package version hook returns all the bytes in file including spaces", func(t *testing.T) {
		testPkgVer := "\r\n   1.2.3-test  \n\t"
		setupPkgVersion(t, testPkgVer, 0o444)
		output := pkgVersHook.Hook(ctx)
		assert.Equal(t, testPkgVer, string(output))
	})
}

func setupPkgVersion(t *testing.T, pkgVer string, fileMode os.FileMode) {
	// setup a fake package version to test the package version hook
	pkgVersPath, err := version.GetAgentPackageVersionFilePath()
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(pkgVersPath) })
	err = os.WriteFile(pkgVersPath, []byte(pkgVer), fileMode)
	require.NoError(t, err)
}

func isVersion(input []byte) (bool, error) {
	return strings.Contains(string(input), "version:"), nil
}

func isPprof(input []byte) (bool, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(input))
	if err != nil {
		return false, err
	}
	uncompressed, err := io.ReadAll(gz)
	if err != nil {
		return false, err
	}
	_, err = profile.ParseUncompressed(uncompressed)
	if err != nil {
		return false, err
	}
	return true, nil
}
