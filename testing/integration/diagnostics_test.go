// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"archive/zip"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/process"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

const diagnosticsArchiveGlobPattern = "elastic-agent-diagnostics-*.zip"

var diagnosticsFiles = []string{
	"allocs.pprof.gz",
	"block.pprog.gz",
	"components-actual.yaml",
	"components-expected.yaml",
	"computed-config.yaml",
	"goroutine.pprof.gz",
	"heap.pprof.gz",
	"local-config.yaml",
	"mutex.pprof.gz",
	"pre-config.yaml",
	"state.yaml",
	"threadcreate.pprof.gz",
	"variables.yaml",
	"version.txt",
}

var unitsDiagnosticsFiles []string = []string{
	"allocs.pprof.gz",
	"block.pprof.gz",
	"goroutine.pprof.gz",
	"heap.pprof.gz",
	"mutex.pprof.gz",
	"threadcreate.pprof.gz",
}

type componentAndUnitNames struct {
	name      string
	unitNames []string
}

type DiagnosticsIntegrationTestSuite struct {
	suite.Suite
	f *integrationtest.Fixture
}

func (s *DiagnosticsIntegrationTestSuite) SetupSuite() {
	f, err := define.NewFixture(s.T())
	s.Require().NoError(err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = f.Prepare(ctx, fakeComponent, fakeShipper)
	s.Require().NoError(err)
	s.f = f
}

func (s *DiagnosticsIntegrationTestSuite) TestDiagnosticsFromHealthyAgent() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testDiagnostics := func() error {
		diagnosticCommandWD := s.T().TempDir()
		diagnosticCmdOutput, err := s.f.Exec(ctx, []string{"diagnostics", "collect"}, process.WithWorkDir(diagnosticCommandWD))

		s.T().Logf("diagnostic command completed with output \n%q\n", diagnosticCmdOutput)
		s.Require().NoErrorf(err, "error running diagnostic command: %v", err)

		s.T().Logf("checking directory %q for the generated archive", diagnosticCommandWD)
		files, err := filepath.Glob(filepath.Join(diagnosticCommandWD, diagnosticsArchiveGlobPattern))
		s.Require().NoError(err)
		s.Require().Len(files, 1)
		s.T().Logf("Found %q diagnostic archive.", files[0])

		// get the version of the running agent
		avi, err := s.getRunningAgentVersion(ctx)
		s.Require().NoError(err)

		verifyDiagnosticArchive(s.T(), ctx, files[0], avi)

		return nil
	}

	err := s.f.Run(ctx, integrationtest.State{
		Configure:  simpleConfig2,
		AgentState: atesting.NewClientState(client.Healthy),
		Components: map[string]atesting.ComponentState{
			"fake-default": {
				State: atesting.NewClientState(client.Healthy),
				Units: map[atesting.ComponentUnitKey]atesting.ComponentUnitState{
					atesting.ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "fake-default"}: {
						State: atesting.NewClientState(client.Healthy),
					},
					atesting.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default-fake"}: {
						State: atesting.NewClientState(client.Healthy),
					},
				},
			},
			"fake-shipper-default": {
				State: atesting.NewClientState(client.Healthy),
				Units: map[atesting.ComponentUnitKey]atesting.ComponentUnitState{
					atesting.ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "fake-shipper-default"}: {
						State: atesting.NewClientState(client.Healthy),
					},
					atesting.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default"}: {
						State: atesting.NewClientState(client.Healthy),
					},
				},
			},
		},
		After: testDiagnostics,
	})
	s.Assert().NoError(err)
}

func verifyDiagnosticArchive(t *testing.T, ctx context.Context, diagArchive string, avi *client.Version) {
	// check that the archive is not an empty file
	stat, err := os.Stat(diagArchive)
	require.NoErrorf(t, err, "stat file %q failed", diagArchive)
	require.Greaterf(t, stat.Size(), int64(0), "file %s has incorrect size", diagArchive)

	// extract the zip file into a temp folder
	extractionDir := t.TempDir()

	extractZipArchive(t, diagArchive, extractionDir)

	expectedDiagArchiveFilePatterns := compileExpectedDiagnosticFilePatterns(avi, []componentAndUnitNames{
		{
			name:      "fake-default",
			unitNames: []string{"fake-default", "fake"},
		},
		{
			name:      "fake-shipper-default",
			unitNames: []string{"fake-shipper-default", "fake-default"},
		},
	})

	expectedExtractedFiles := map[string]struct{}{}
	for _, filePattern := range expectedDiagArchiveFilePatterns {
		absFilePattern := filepath.Join(extractionDir, filePattern.pattern)
		files, err := filepath.Glob(absFilePattern)
		assert.NoErrorf(t, err, "error globbing with pattern %q", absFilePattern)
		min := 0
		if filePattern.optional {
			min = -1
		}
		assert.Greaterf(t, len(files), min, "glob pattern %q matched no files", absFilePattern)
		for _, f := range files {
			expectedExtractedFiles[f] = struct{}{}
		}
	}

	actualExtractedDiagFiles := map[string]struct{}{}

	err = filepath.Walk(extractionDir, func(path string, info fs.FileInfo, err error) error {
		require.NoErrorf(t, err, "error walking extracted path %q", path)

		// we are not interested in directories
		if !info.IsDir() {
			actualExtractedDiagFiles[path] = struct{}{}
			assert.Greaterf(t, info.Size(), int64(0), "file %q has an invalid size", path)
		}

		return nil
	})
	require.NoErrorf(t, err, "error walking output directory %q", extractionDir)

	assert.ElementsMatch(t, extractKeysFromMap(expectedExtractedFiles), extractKeysFromMap(actualExtractedDiagFiles))
}

func TestDiagnosticsCommandIntegrationTestSuite(t *testing.T) {
	define.Require(t, define.Requirements{
		Local: true,
	})
	suite.Run(t, new(DiagnosticsIntegrationTestSuite))
}

func extractZipArchive(t *testing.T, zipFile string, dst string) {
	zReader, err := zip.OpenReader(zipFile)
	require.NoErrorf(t, err, "file %q is not a valid zip archive", zipFile)
	defer zReader.Close()

	t.Logf("extracting diagnostic archive in dir %q", dst)
	for _, zf := range zReader.File {
		filePath := filepath.Join(dst, zf.Name)
		t.Logf("unzipping file %q", filePath)
		require.Truef(t, strings.HasPrefix(filePath, filepath.Clean(dst)+string(os.PathSeparator)), "file %q points outside of extraction dir %q", filePath, dst)

		if zf.FileInfo().IsDir() {
			t.Logf("creating directory %q", filePath)
			os.MkdirAll(filePath, os.ModePerm)
			continue
		}

		err = os.MkdirAll(filepath.Dir(filePath), os.ModePerm)
		require.NoErrorf(t, err, "error creating parent folder for file %q", filePath)

		extractSingleFileFromArchive(t, zf, filePath)

	}
}

func extractSingleFileFromArchive(t *testing.T, src *zip.File, dst string) {
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, src.Mode())
	require.NoErrorf(t, err, "error creating extracted file %q", dst)

	defer dstFile.Close()

	srcFile, err := src.Open()
	require.NoErrorf(t, err, "error opening zipped file %q", src.Name)

	defer srcFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	require.NoErrorf(t, err, "error copying content from zipped file %q to extracted file %q", src.Name, dst)
}

func (s *DiagnosticsIntegrationTestSuite) getRunningAgentVersion(ctx context.Context) (*client.Version, error) {
	avi, err := s.f.Client().Version(ctx)
	s.Require().NoErrorf(err, "error executing version command")
	return &avi, err
}

func compileExpectedDiagnosticFilePatterns(avi *client.Version, comps []componentAndUnitNames) []filePattern {
	files := make([]filePattern, 0, len(diagnosticsFiles)+len(comps)*len(unitsDiagnosticsFiles))

	for _, file := range diagnosticsFiles {
		files = append(files, filePattern{
			pattern:  file,
			optional: false,
		})
	}

	for _, comp := range comps {
		for _, unitName := range comp.unitNames {
			unitPath := path.Join("components", comp.name, unitName)
			for _, fileName := range unitsDiagnosticsFiles {
				files = append(files,
					filePattern{
						pattern:  path.Join(unitPath, fileName),
						optional: false,
					})
			}
		}
	}

	files = append(files, filePattern{
		pattern:  path.Join("logs", "elastic-agent-"+avi.Commit[:6], "elastic-agent-*.ndjson"),
		optional: false,
	})
	// this pattern overlaps with the previous one but filepath.Glob() does not seem to match using '?' wildcard
	// optional: it doesn't have to be there (in some cases the watcher has not written any logs)
	files = append(files, filePattern{
		pattern:  path.Join("logs", "elastic-agent-"+avi.Commit[:6], "elastic-agent-watcher-*.ndjson"),
		optional: true,
	})

	return files
}

func extractKeysFromMap[K comparable, V any](src map[K]V) []K {
	keys := make([]K, 0, len(src))
	for k := range src {
		keys = append(keys, k)
	}
	return keys
}

type filePattern struct {
	pattern  string
	optional bool
}
