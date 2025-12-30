// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/elastic/elastic-agent/testing/integration"
)

const diagnosticsArchiveGlobPattern = "elastic-agent-diagnostics-*.zip"

var diagnosticsFiles = []string{
	"package.version",
	"agent-info.yaml",
	"allocs.pprof.gz",
	"block.pprof.gz",
	"components-actual.yaml",
	"components-expected.yaml",
	"computed-config.yaml",
	"environment.yaml",
	"goroutine.pprof.gz",
	"heap.pprof.gz",
	"local-config.yaml",
	"mutex.pprof.gz",
	"otel.yaml",
	"otel-merged.yaml",
	"pre-config.yaml",
	"local-config.yaml",
	"state.yaml",
	"threadcreate.pprof.gz",
	"variables.yaml",
	"version.txt",
}

var compDiagnosticsFiles = []string{
	"allocs.pprof.gz",
	"block.pprof.gz",
	"goroutine.pprof.gz",
	"heap.pprof.gz",
	"mutex.pprof.gz",
	"threadcreate.pprof.gz",
}

var componentSetup = map[string]integrationtest.ComponentState{
	"fake-default": {
		State: integrationtest.NewClientState(client.Healthy),
		Units: map[integrationtest.ComponentUnitKey]integrationtest.ComponentUnitState{
			integrationtest.ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "fake-default"}: {
				State: integrationtest.NewClientState(client.Healthy),
			},
			integrationtest.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default-fake"}: {
				State: integrationtest.NewClientState(client.Healthy),
			},
		},
	},
}

var isolatedUnitsComponentSetup = map[string]integrationtest.ComponentState{
	"fake-isolated-units-default-fake-isolated-units": {
		State: integrationtest.NewClientState(client.Healthy),
		Units: map[integrationtest.ComponentUnitKey]integrationtest.ComponentUnitState{
			integrationtest.ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "fake-isolated-units-default-fake-isolated-units"}: {
				State: integrationtest.NewClientState(client.Healthy),
			},
			integrationtest.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-isolated-units-default-fake-isolated-units-unit"}: {
				State: integrationtest.NewClientState(client.Healthy),
			},
		},
	},
	"fake-isolated-units-default-fake-isolated-units-1": {
		State: integrationtest.NewClientState(client.Healthy),
		Units: map[integrationtest.ComponentUnitKey]integrationtest.ComponentUnitState{
			integrationtest.ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "fake-isolated-units-default-fake-isolated-units-1"}: {
				State: integrationtest.NewClientState(client.Healthy),
			},
			integrationtest.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-isolated-units-default-fake-isolated-units-1-unit"}: {
				State: integrationtest.NewClientState(client.Healthy),
			},
		},
	},
}

type componentAndUnitNames struct {
	name      string
	unitNames []string
}

func TestDiagnosticsOptionalValues(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: false,
	})

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	diagpprof := append(diagnosticsFiles, "cpu.pprof")
	diagCompPprof := append(compDiagnosticsFiles, "cpu.pprof")

	err = fixture.Run(ctx, integrationtest.State{
		Configure:  simpleConfig2,
		AgentState: integrationtest.NewClientState(client.Healthy),
		Components: componentSetup,
		After:      testDiagnosticsFactory(t, componentSetup, diagpprof, diagCompPprof, fixture, []string{"diagnostics", "-p"}),
	})
	require.NoError(t, err)
}

func TestIsolatedUnitsDiagnosticsOptionalValues(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: false,
	})

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	diagpprof := append(diagnosticsFiles, "cpu.pprof")
	diagCompPprof := append(compDiagnosticsFiles, "cpu.pprof")

	err = fixture.Run(ctx, integrationtest.State{
		Configure:  complexIsolatedUnitsConfig,
		AgentState: integrationtest.NewClientState(client.Healthy),
		Components: isolatedUnitsComponentSetup,
		After:      testDiagnosticsFactory(t, isolatedUnitsComponentSetup, diagpprof, diagCompPprof, fixture, []string{"diagnostics", "-p"}),
	})
	require.NoError(t, err)
}

func TestDiagnosticsCommand(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: false,
	})

	f, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = f.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	err = f.Run(ctx, integrationtest.State{
		Configure:  simpleConfig2,
		AgentState: integrationtest.NewClientState(client.Healthy),
		Components: componentSetup,
		After:      testDiagnosticsFactory(t, componentSetup, diagnosticsFiles, compDiagnosticsFiles, f, []string{"diagnostics", "collect"}),
	})
	assert.NoError(t, err)
}

func TestIsolatedUnitsDiagnosticsCommand(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: false,
	})

	f, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = f.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	err = f.Run(ctx, integrationtest.State{
		Configure:  complexIsolatedUnitsConfig,
		AgentState: integrationtest.NewClientState(client.Healthy),
		Components: isolatedUnitsComponentSetup,
		After:      testDiagnosticsFactory(t, isolatedUnitsComponentSetup, diagnosticsFiles, compDiagnosticsFiles, f, []string{"diagnostics", "collect"}),
	})
	assert.NoError(t, err)
}

func TestRedactFleetSecretPathsDiagnostics(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Local: false,
		Sudo:  true,
	})

	ctx, cancel := testcontext.WithTimeout(t, context.Background(), time.Minute*10)
	defer cancel()

	t.Log("Setup fake fleet-server")
	apiKey, policy := createBasicFleetPolicyData(t, "http://fleet-server:8220")
	checkinWithAcker := fleetservertest.NewCheckinActionsWithAcker()
	fleet := fleetservertest.NewServerWithHandlers(
		apiKey,
		"enrollmentToken",
		policy.AgentID,
		policy.PolicyID,
		checkinWithAcker.ActionsGenerator(),
		checkinWithAcker.Acker(),
		fleetservertest.WithRequestLog(t.Logf),
	)
	defer fleet.Close()
	policyChangeAction, err := fleetservertest.NewActionPolicyChangeWithFakeComponent("test-policy-change", fleetservertest.TmplPolicy{
		AgentID:    policy.AgentID,
		PolicyID:   policy.PolicyID,
		FleetHosts: []string{fleet.LocalhostURL},
	})
	require.NoError(t, err)
	checkinWithAcker.AddCheckin("token", 0, policyChangeAction)

	t.Log("Enroll agent in fake fleet-server")
	fixture, err := define.NewFixtureFromLocalBuild(t,
		define.Version(),
		integrationtest.WithAllowErrors(),
		integrationtest.WithLogOutput())
	require.NoError(t, err, "SetupTest: NewFixtureFromLocalBuild failed")
	err = fixture.EnsurePrepared(ctx)
	require.NoError(t, err, "SetupTest: fixture.Prepare failed")

	out, err := fixture.Install(
		ctx,
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			Privileged:     false,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             fleet.LocalhostURL,
				EnrollmentToken: "anythingWillDO",
			}})
	require.NoErrorf(t, err, "Error when installing agent, output: %s", out)
	check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)

	// wait until the agent acknowledges the policy change
	require.Eventually(t, func() bool {
		return checkinWithAcker.Acked(policyChangeAction.ActionID)
	}, time.Minute, time.Second)

	t.Log("Gather diagnostics.")
	diagZip, err := fixture.ExecDiagnostics(ctx)
	require.NoError(t, err, "error when gathering diagnostics")
	stat, err := os.Stat(diagZip)
	require.NoErrorf(t, err, "stat file %q failed", diagZip)
	require.Greaterf(t, stat.Size(), int64(0), "file %s has incorrect size", diagZip)

	t.Log("Check if config files have been redacted.")
	extractionDir := t.TempDir()
	extractZipArchive(t, diagZip, extractionDir)
	fileNames := []string{
		"pre-config.yaml",
		"computed-config.yaml",
		"components-expected.yaml",
		"components-actual.yaml",
	}

	var checkRedacted func(any) error
	checkRedacted = func(root any) error {
		switch root := root.(type) {
		case map[string]any:
			for rootKey, value := range root {
				if rootKey == "custom_attr" {
					if value != "<REDACTED>" {
						return fmt.Errorf("found non-redacted value in %q", rootKey)
					}
				}
				return checkRedacted(value)
			}
		case []any:
			for _, value := range root {
				return checkRedacted(value)
			}
		default:
			// ignore other types
		}
		return nil
	}

	for _, fileName := range fileNames {
		path := filepath.Join(extractionDir, fileName)
		stat, err := os.Stat(path)
		require.NoErrorf(t, err, "stat file %q failed", path)
		require.Greaterf(t, stat.Size(), int64(0), "file %s has incorrect size", path)
		f, err := os.Open(path)
		require.NoErrorf(t, err, "open file %q failed", path)
		defer f.Close()

		var yObj map[string]any
		err = yaml.NewDecoder(f).Decode(&yObj)
		require.NoError(t, err)

		err = checkRedacted(yObj)
		require.NoError(t, err, "file %q has non-redacted values", path)
	}
}

func TestBeatDiagnostics(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: false,
	})

	configTemplate := `
inputs:
  - id: filestream-filebeat
    type: filestream
    paths:
      - {{ .InputFile }}
    prospector.scanner.fingerprint.enabled: false
    file_identity.native: ~
    use_output: default
outputs:
  default:
    type: elasticsearch
    hosts: [http://localhost:9200]
    api_key: placeholder
    status_reporting:
      enabled: false
agent.monitoring.enabled: false
agent.internal.runtime.filebeat.filestream: {{ .Runtime }}
`

	var filebeatSetup = map[string]integrationtest.ComponentState{
		"filestream-default": {
			State: integrationtest.NewClientState(client.Healthy),
		},
	}

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	expectedComponentState := map[string]integrationtest.ComponentState{
		"filestream-default": {
			State: integrationtest.NewClientState(client.Healthy),
			Units: map[integrationtest.ComponentUnitKey]integrationtest.ComponentUnitState{
				integrationtest.ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "filestream-default"}: {
					State: integrationtest.NewClientState(client.Healthy),
				},
				integrationtest.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "filestream-default-filestream-filebeat"}: {
					State: integrationtest.NewClientState(client.Healthy),
				},
			},
		},
	}
	expectedAgentState := integrationtest.NewClientState(client.Healthy)

	testCases := []struct {
		name                         string
		runtime                      string
		expectedCompDiagnosticsFiles []string
	}{
		{
			name:    "filebeat process",
			runtime: "process",
			expectedCompDiagnosticsFiles: append(compDiagnosticsFiles,
				"registry.tar.gz",
				"input_metrics.json",
				"beat_metrics.json",
				"beat-rendered-config.yml",
				"global_processors.txt",
			),
		},
		{
			name:    "filebeat receiver",
			runtime: "otel",
			expectedCompDiagnosticsFiles: []string{
				"registry.tar.gz",
				"beat_metrics.json",
				"input_metrics.json",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create the fixture
			f, err := define.NewFixtureFromLocalBuild(t, define.Version(), integrationtest.WithAllowErrors())
			require.NoError(t, err)
			err = f.Prepare(ctx)
			require.NoError(t, err)

			// Create the data file to ingest
			inputFile, err := os.CreateTemp(t.TempDir(), "input.txt")
			require.NoError(t, err, "failed to create temp file to hold data to ingest")
			t.Cleanup(func() {
				cErr := inputFile.Close()
				assert.NoError(t, cErr)
			})
			_, err = inputFile.WriteString("hello world\n")
			require.NoError(t, err, "failed to write data to temp file")

			var configBuffer bytes.Buffer
			require.NoError(t,
				template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer, map[string]any{
					"Runtime":   tc.runtime,
					"InputFile": inputFile.Name(),
				}))
			expDiagFiles := append([]string{}, diagnosticsFiles...)
			if tc.runtime == "otel" {
				// EDOT adds these extra files.
				// TestBeatDiagnostics is quite strict about what it expects to see in the archive.
				expDiagFiles = append(expDiagFiles,
					"edot/goroutine.profile.gz",
					"edot/heap.profile.gz",
					"edot/allocs.profile.gz",
					"edot/block.profile.gz",
					"edot/mutex.profile.gz",
					"edot/threadcreate.profile.gz",
					"edot/otel-merged-actual.yaml")
			}
			err = f.Run(ctx, integrationtest.State{
				Configure:  configBuffer.String(),
				AgentState: expectedAgentState,
				Components: expectedComponentState,
				After:      testDiagnosticsFactory(t, filebeatSetup, expDiagFiles, tc.expectedCompDiagnosticsFiles, f, []string{"diagnostics", "collect"}),
			})
			assert.NoError(t, err)
		})
	}
}

func TestEDOTDiagnostics(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: false,
	})

	configTemplate := `
inputs:
  - id: filestream-filebeat
    type: filestream
    paths:
      - {{ .InputFile }}
    prospector.scanner.fingerprint.enabled: false
    file_identity.native: ~
    use_output: default
agent.grpc:
    port: 6790
outputs:
  default:
    type: elasticsearch
    hosts: [http://localhost:9200]
    api_key: placeholder
agent.monitoring.enabled: false
agent.internal.runtime.filebeat.filestream: otel
`

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Create the fixture
	f, err := define.NewFixtureFromLocalBuild(t, define.Version(), integrationtest.WithAllowErrors())
	require.NoError(t, err)

	// Create the data file to ingest
	inputFile, err := os.CreateTemp(t.TempDir(), "input.txt")
	require.NoError(t, err, "failed to create temp file to hold data to ingest")
	t.Cleanup(func() {
		cErr := inputFile.Close()
		assert.NoError(t, cErr)
	})
	_, err = inputFile.WriteString("hello world\n")
	require.NoError(t, err, "failed to write data to temp file")

	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer, map[string]any{
			"InputFile": inputFile.Name(),
		}))
	err = f.Prepare(ctx)
	require.NoError(t, err)

	err = f.Configure(ctx, configBuffer.Bytes())
	require.NoError(t, err)
	cmd, err := f.PrepareAgentCommand(ctx, []string{"-e"})
	require.NoError(t, err)

	output := strings.Builder{}
	cmd.Stderr = &output
	cmd.Stdout = &output

	err = cmd.Start()
	require.NoError(t, err)

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		err = f.IsHealthyOrDegradedFromOutput(ctx)
		require.NoErrorf(collect, err, "agent is not healthy: %s", err)
		require.Containsf(collect, output.String(), "Diagnostics extension started", "expected log: %s", output.String())
	}, 30*time.Second, 1*time.Second)

	diagZip, err := f.ExecDiagnostics(ctx)
	extractionDir := t.TempDir()

	stat, err := os.Stat(diagZip)
	require.NoErrorf(t, err, "stat file %q failed", diagZip)
	require.Greaterf(t, stat.Size(), int64(0), "file %s has incorrect size", diagZip)

	extractZipArchive(t, diagZip, extractionDir)

	expectedFiles := []string{
		"edot/otel-merged-actual.yaml",
		"edot/allocs.profile.gz",
		"edot/block.profile.gz",
		"edot/goroutine.profile.gz",
		"edot/heap.profile.gz",
		"edot/mutex.profile.gz",
		"edot/threadcreate.profile.gz",
		"components/filestream-default/registry.tar.gz",
		"components/filestream-default/beat_metrics.json",
		"components/filestream-default/input_metrics.json",
	}

	for _, f := range expectedFiles {
		path := filepath.Join(extractionDir, f)
		stat, err := os.Stat(path)
		require.NoErrorf(t, err, "stat file %q failed", path)
		require.Greaterf(t, stat.Size(), int64(0), "file %s has incorrect size", path)
	}
	verifyFilebeatRegistry(t, filepath.Join(extractionDir, "components/filestream-default/registry.tar.gz"))
}

func testDiagnosticsFactory(t *testing.T, compSetup map[string]integrationtest.ComponentState, diagFiles []string, diagCompFiles []string, fix *integrationtest.Fixture, cmd []string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		diagZip, err := fix.ExecDiagnostics(ctx, cmd...)

		// get the version of the running agent
		avi, err := getRunningAgentVersion(ctx, fix)
		require.NoError(t, err)

		verifyDiagnosticArchive(t, compSetup, diagZip, diagFiles, diagCompFiles, avi)

		// preserve the diagnostic archive if the test failed
		if t.Failed() {
			fix.MoveToDiagnosticsDir(diagZip)
		}

		return nil
	}
}

func verifyDiagnosticArchive(t *testing.T, compSetup map[string]integrationtest.ComponentState, diagArchive string, diagFiles []string, diagCompFiles []string, avi *client.Version) {
	// check that the archive is not an empty file
	stat, err := os.Stat(diagArchive)
	require.NoErrorf(t, err, "stat file %q failed", diagArchive)
	require.Greaterf(t, stat.Size(), int64(0), "file %s has incorrect size", diagArchive)

	// extract the zip file into a temp folder
	extractionDir := t.TempDir()

	extractZipArchive(t, diagArchive, extractionDir)

	compAndUnitNames := extractComponentAndUnitNames(compSetup)
	expectedDiagArchiveFilePatterns := compileExpectedDiagnosticFilePatterns(avi, diagFiles, diagCompFiles, compAndUnitNames)

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

	err = filepath.WalkDir(extractionDir, func(path string, entry fs.DirEntry, err error) error {
		require.NoErrorf(t, err, "error walking extracted path %q", path)

		// we are not interested in directories
		if !entry.IsDir() {
			actualExtractedDiagFiles[path] = struct{}{}
			info, err := entry.Info()
			require.NoError(t, err, path)
			assert.Greaterf(t, info.Size(), int64(0), "file %q has an invalid size", path)
		}

		return nil
	})
	require.NoErrorf(t, err, "error walking output directory %q", extractionDir)

	assert.ElementsMatch(t, extractKeysFromMap(expectedExtractedFiles), extractKeysFromMap(actualExtractedDiagFiles))
}

func extractComponentAndUnitNames(compSetup map[string]integrationtest.ComponentState) []componentAndUnitNames {
	comps := make([]componentAndUnitNames, 0, len(compSetup))
	for compName, compState := range compSetup {
		unitNames := make([]string, 0, len(compState.Units))
		for unitKey := range compState.Units {
			unitNames = append(unitNames, unitKey.UnitID)
		}
		comps = append(comps, componentAndUnitNames{
			name:      compName,
			unitNames: unitNames,
		})
	}
	return comps
}

func extractZipArchive(t *testing.T, zipFile string, dst string) {
	t.Helper()

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
			err := os.MkdirAll(filePath, os.ModePerm)
			assert.NoError(t, err)
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

func getRunningAgentVersion(ctx context.Context, f *integrationtest.Fixture) (*client.Version, error) {
	avi, err := f.Client().Version(ctx)
	if err != nil {
		return nil, err
	}

	return &avi, err
}

func compileExpectedDiagnosticFilePatterns(avi *client.Version, diagfiles []string, diagCompFiles []string, comps []componentAndUnitNames) []filePattern {
	files := make([]filePattern, 0, len(diagnosticsFiles)+len(comps)*len(compDiagnosticsFiles))

	for _, file := range diagfiles {
		files = append(files, filePattern{
			pattern:  file,
			optional: false,
		})
	}

	for _, comp := range comps {
		compPath := path.Join("components", comp.name)
		for _, fileName := range diagCompFiles {
			files = append(files,
				filePattern{
					pattern:  path.Join(compPath, fileName),
					optional: false,
				})
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

func verifyFilebeatRegistry(t *testing.T, path string) {
	data, err := os.ReadFile(path)
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
	assert.Equal(t, filepath.Join("registry", "filebeat", "log.json"), hdr.Name)
	hdr, err = tarReader.Next()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("registry", "filebeat", "meta.json"), hdr.Name)
}
