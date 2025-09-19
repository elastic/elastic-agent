// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	component2 "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"

	componentruntime "github.com/elastic/elastic-agent/pkg/component/runtime"
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

	expectedDiags := []componentruntime.ComponentDiagnostic{
		{
			Component: filebeatComp,
		},
		{
			Component: otherComp,
		},
	}

	diags, err := m.PerformComponentDiagnostics(t.Context(), nil)
	require.NoError(t, err)
	for i, d := range diags {
		assert.Equal(t, expectedDiags[i].Component.ID, d.Component.ID)
		// we should have errors set about not being able to connect to monitoring endpoints
		require.NotNil(t, d.Err)
		assert.ErrorContains(t, d.Err, "failed to get stats beat metrics")
		assert.ErrorContains(t, d.Err, "failed to get input beat metrics")
		if translate.GetBeatNameForComponent(&d.Component) == "filebeat" {
			assert.ErrorContains(t, d.Err, "failed to get filebeat registry archive")
		}
	}
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
		expectedDiags := []componentruntime.ComponentUnitDiagnostic{
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
		req := componentruntime.ComponentUnitDiagnosticRequest{
			Component: filebeatComp,
			Unit:      filebeatComp.Units[0],
		}
		expectedDiags := []componentruntime.ComponentUnitDiagnostic{
			{
				Component: filebeatComp,
				Unit:      filebeatComp.Units[0],
			},
		}
		diags := m.PerformDiagnostics(t.Context(), req)
		assert.Equal(t, expectedDiags, diags)
	})
}

func TestBeatMetrics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skip test on Windows.",
			"It's technically cumbersome to set up an npipe http server.",
			"And it doesn't have anything to do with the code paths being tested.",
		)
	}
	setTemporaryAgentPath(t)
	logger, obs := loggertest.New("test")
	compID := "filebeat-comp-1"

	filebeatComp := testComponent(compID)
	filebeatComp.InputSpec.Spec.Command.Args = []string{"filebeat"}

	m := &OTelManager{
		logger:     logger,
		components: []component.Component{filebeatComp},
	}
	expectedMetricData, err := json.MarshalIndent(map[string]any{"test": "test"}, "", "  ")
	require.NoError(t, err)

	fileName := strings.TrimPrefix(component2.BeatsMonitoringEndpoint(compID), fmt.Sprintf("%s://", utils.SocketScheme))
	err = os.MkdirAll(filepath.Dir(fileName), 0o755)
	require.NoError(t, err)

	listener, err := net.Listen("unix", fileName)
	require.NoError(t, err)
	server := http.Server{
		ReadHeaderTimeout: time.Second, // needed to silence gosec
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, wErr := w.Write(expectedMetricData)
			require.NoError(t, wErr)
		})}
	go func() {
		sErr := server.Serve(listener)
		assert.ErrorIs(t, sErr, http.ErrServerClosed)
	}()
	t.Cleanup(func() {
		cErr := server.Close()
		assert.NoError(t, cErr)
	})

	diags, err := m.PerformComponentDiagnostics(t.Context(), nil)
	require.NoError(t, err)
	assert.Len(t, obs.All(), 0)
	require.Len(t, diags, 1)

	diag := diags[0]
	assert.Equal(t, filebeatComp, diag.Component)
	// two metrics diagnostics and one filebeat registry
	require.Len(t, diag.Results, 2, "expected 2 diagnostics, got error: %w", diag.Err)

	t.Run("stats beat metrics", func(t *testing.T) {
		beatMetrics := diag.Results[0]
		assert.Equal(t, "beat_metrics", beatMetrics.Name)
		assert.Equal(t, "Metrics from the default monitoring namespace and expvar.", beatMetrics.Description)
		assert.Equal(t, "beat_metrics.json", beatMetrics.Filename)
		assert.Equal(t, "application/json", beatMetrics.ContentType)
		assert.Equal(t, expectedMetricData, beatMetrics.Content)
	})

	t.Run("input beat metrics", func(t *testing.T) {
		inputMetrics := diag.Results[1]
		assert.Equal(t, "input_metrics", inputMetrics.Name)
		assert.Equal(t, "Metrics from active inputs.", inputMetrics.Description)
		assert.Equal(t, "input_metrics.json", inputMetrics.Filename)
		assert.Equal(t, "application/json", inputMetrics.ContentType)
		assert.Equal(t, expectedMetricData, inputMetrics.Content)
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
