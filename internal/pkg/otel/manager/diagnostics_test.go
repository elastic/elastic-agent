// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/component"
)

func TestPerformComponentDiagnostics(t *testing.T) {
	logger, _ := loggertest.New("test")
	compID := "filebeat-comp-1"

	filebeatComp := testComponent(compID)
	filebeatComp.InputSpec.Spec.Command.Args = []string{"filebeat"}

	otherComp := testComponent("other-comp")
	otherComp.InputSpec.Spec.Command.Args = []string{"metricbeat"}

	m := &OTelManager{
		logger:     logger,
		components: []component.Component{filebeatComp, otherComp},
	}

	expectedDiags := []runtime.ComponentDiagnostic{
		{
			Component: filebeatComp,
		},
		{
			Component: otherComp,
		},
	}

	diags, err := m.PerformComponentDiagnostics(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, expectedDiags, diags)
}

func TestPerformDiagnostics(t *testing.T) {
	logger, _ := loggertest.New("test")
	compID := "filebeat-comp-1"

	filebeatComp := testComponent(compID)
	filebeatComp.InputSpec.Spec.Command.Args = []string{"filebeat"}

	otherComp := testComponent("other-comp")
	otherComp.InputSpec.Spec.Command.Args = []string{"metricbeat"}

	m := &OTelManager{
		logger:     logger,
		components: []component.Component{filebeatComp, otherComp},
	}

	t.Run("diagnose all units when no request is provided", func(t *testing.T) {
		expectedDiags := []runtime.ComponentUnitDiagnostic{
			{
				Component: filebeatComp,
				Unit:      filebeatComp.Units[0],
			},
			{
				Component: filebeatComp,
				Unit:      filebeatComp.Units[1],
			},
			{
				Component: otherComp,
				Unit:      otherComp.Units[0],
			},
			{
				Component: otherComp,
				Unit:      otherComp.Units[1],
			},
		}
		diags := m.PerformDiagnostics(t.Context())
		assert.Equal(t, expectedDiags, diags)
	})

	t.Run("diagnose specific unit", func(t *testing.T) {
		req := runtime.ComponentUnitDiagnosticRequest{
			Component: filebeatComp,
			Unit:      filebeatComp.Units[0],
		}
		expectedDiags := []runtime.ComponentUnitDiagnostic{
			{
				Component: filebeatComp,
				Unit:      filebeatComp.Units[0],
			},
		}
		diags := m.PerformDiagnostics(t.Context(), req)
		assert.Equal(t, expectedDiags, diags)
	})
}

func TestMatchRegistryFiles(t *testing.T) {
	regexps := getRegexpsForRegistryFiles()
	testCases := []struct {
		path     string
		expected bool
	}{
		{"registry", true},
		{filepath.Join("registry", "filebeat"), true},
		{filepath.Join("registry", "filebeat", "meta.json"), true},
		{filepath.Join("registry", "filebeat", "log.json"), true},
		{filepath.Join("registry", "filebeat", "active.dat"), true},
		{filepath.Join("registry", "filebeat", "12345.json"), true},
		{filepath.Join("registry", "filebeat", "other.txt"), false},
		{"not_registry", false},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.expected, matchRegistryFiles(regexps, tc.path))
		})
	}
}

func TestTarFolder(t *testing.T) {
	logger, _ := loggertest.New("test")

	// Create a temporary source directory
	srcDir, err := os.MkdirTemp("", "src")
	require.NoError(t, err)
	defer os.RemoveAll(srcDir)

	// Create registry structure
	registryDir := filepath.Join(srcDir, "registry")
	filebeatDir := filepath.Join(registryDir, "filebeat")
	require.NoError(t, os.MkdirAll(filebeatDir, 0755))

	// Create files
	filesToCreate := []string{
		filepath.Join(filebeatDir, "meta.json"),
		filepath.Join(filebeatDir, "log.json"),
		filepath.Join(filebeatDir, "123.json"),
		filepath.Join(filebeatDir, "should_be_ignored.txt"),
	}
	for _, f := range filesToCreate {
		require.NoError(t, os.WriteFile(f, []byte("test data"), 0644))
	}

	// Tar the folder
	var buf bytes.Buffer
	err = tarFolder(logger, &buf, registryDir)
	require.NoError(t, err)

	// Verify the tar contents
	tarReader := tar.NewReader(&buf)
	foundFiles := make(map[string]bool)
	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		foundFiles[hdr.Name] = true
	}

	assert.True(t, foundFiles[filepath.Join("registry", "filebeat", "meta.json")])
	assert.True(t, foundFiles[filepath.Join("registry", "filebeat", "log.json")])
	assert.True(t, foundFiles[filepath.Join("registry", "filebeat", "123.json")])
	assert.False(t, foundFiles[filepath.Join("registry", "filebeat", "should_be_ignored.txt")])
}

func TestFileBeatRegistryPath(t *testing.T) {
	compID := "test-component"
	expectedPath := filepath.Join(paths.Run(), compID, "registry")
	assert.Equal(t, expectedPath, FileBeatRegistryPath(compID))
}

func TestFileBeatRegistryTarGz(t *testing.T) {
	logger, _ := loggertest.New("test")
	compID := "filebeat-comp-1"

	setTemporaryAgentPath(t)
	registryPath := FileBeatRegistryPath(compID)
	require.NoError(t, os.MkdirAll(filepath.Join(registryPath, "filebeat"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(registryPath, "filebeat", "meta.json"), []byte("test"), 0644))

	t.Run("creates a valid tar.gz", func(t *testing.T) {
		data, err := FileBeatRegistryTarGz(logger, compID)
		require.NoError(t, err)

		gzReader, err := gzip.NewReader(bytes.NewReader(data))
		require.NoError(t, err)
		tarReader := tar.NewReader(gzReader)
		hdr, err := tarReader.Next()
		require.NoError(t, err)
		assert.Equal(t, "registry", hdr.Name)
		hdr, err = tarReader.Next()
		require.NoError(t, err)
		assert.Equal(t, filepath.Join("registry", "filebeat"), hdr.Name)
		hdr, err = tarReader.Next()
		require.NoError(t, err)
		assert.Equal(t, filepath.Join("registry", "filebeat", "meta.json"), hdr.Name)
	})

	t.Run("returns error if registry is too large", func(t *testing.T) {
		// Temporarily change the regex to include a large file
		originalRegexps := fileBeatRegistryPathRegExps
		fileBeatRegistryPathRegExps = []*regexp.Regexp{regexp.MustCompile(".*")}
		defer func() { fileBeatRegistryPathRegExps = originalRegexps }()

		largeFilePath := filepath.Join(registryPath, "largefile.log")
		largeData := make([]byte, 21*1024*1024) // 21MB
		_, err := rand.Read(largeData)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(largeFilePath, largeData, 0644))
		defer os.Remove(largeFilePath)

		_, err = FileBeatRegistryTarGz(logger, compID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "registry is too large for diagnostics")
	})
}

func setTemporaryAgentPath(t *testing.T) {
	topPath := paths.Top()
	tempTopPath := t.TempDir()
	paths.SetTop(tempTopPath)
	t.Cleanup(func() {
		paths.SetTop(topPath)
	})
}
