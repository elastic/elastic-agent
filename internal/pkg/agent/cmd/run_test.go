// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/enroll"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var (
	//go:embed testdata/run/singlelogging.yaml
	singleLoggingConfig []byte

	//go:embed testdata/run/splitlogging.yaml
	splitLoggingConfig []byte
)

func Test_initTracer(t *testing.T) {
	tenPercentSamplingRate := float32(0.1)

	type args struct {
		agentName string
		version   string
		mcfg      *monitoringCfg.MonitoringConfig
	}
	tests := []struct {
		name    string
		args    args
		want    assert.ValueAssertionFunc // value assertion for *apm.Tracer returned by initTracer
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "monitoring config disabled",
			args: args{
				agentName: "testagent",
				version:   "1.2.3",
				mcfg: &monitoringCfg.MonitoringConfig{
					Enabled: false,
				},
			},
			want:    assert.Nil,
			wantErr: assert.NoError,
		},
		{
			name: "monitoring config enabled but traces disabled",
			args: args{
				agentName: "testagent",
				version:   "1.2.3",
				mcfg: &monitoringCfg.MonitoringConfig{
					Enabled:       true,
					MonitorTraces: false,
				},
			},
			want:    assert.Nil,
			wantErr: assert.NoError,
		},
		{
			name: "traces enabled, no TLS",
			args: args{
				agentName: "testagent",
				version:   "1.2.3",
				mcfg: &monitoringCfg.MonitoringConfig{
					Enabled:       true,
					MonitorTraces: true,
					APM: monitoringCfg.APMConfig{
						Environment: "unit-test",
						APIKey:      "api-key",
						SecretToken: "secret-token",
						Hosts:       []string{"localhost:8888"},
						GlobalLabels: map[string]string{
							"k1": "v1",
							"k2": "v2",
						},
						TLS:          monitoringCfg.APMTLS{},
						SamplingRate: &tenPercentSamplingRate,
					},
				},
			},
			want:    assert.NotNil,
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := initTracer(tt.args.agentName, tt.args.version, tt.args.mcfg)
			if got != nil {
				t.Cleanup(func() {
					got.Close()
				})
			}
			if !tt.wantErr(t, err, fmt.Sprintf("initTracer(%v, %v, %v)", tt.args.agentName, tt.args.version, tt.args.mcfg)) {
				return
			}
			tt.want(t, got, "initTracer(%v, %v, %v)", tt.args.agentName, tt.args.version, tt.args.mcfg)
		})
	}
}

func TestRunLoadConfig(t *testing.T) {
	tests := []struct {
		name   string
		file   []byte
		expect func() *configuration.Configuration
	}{{
		name: "single logging entry",
		file: singleLoggingConfig,
		expect: func() *configuration.Configuration {
			cfg := configuration.DefaultConfiguration()
			cfg.Settings.LoggingConfig.Level = logp.DebugLevel
			cfg.Settings.LoggingConfig.ToFiles = true
			cfg.Settings.LoggingConfig.ToStderr = false

			return cfg
		},
	}, {
		name: "split logging entries",
		file: splitLoggingConfig,
		expect: func() *configuration.Configuration {
			cfg := configuration.DefaultConfiguration()
			cfg.Settings.LoggingConfig.Level = logp.DebugLevel
			cfg.Settings.LoggingConfig.ToFiles = true
			cfg.Settings.LoggingConfig.ToStderr = false

			return cfg
		},
	}}

	origCfgDir := paths.Config()
	t.Cleanup(func() { paths.SetConfig(origCfgDir) })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			paths.SetConfig(dir)
			err := os.WriteFile(filepath.Join(dir, paths.DefaultConfigName), tt.file, 0o644)
			require.NoError(t, err)

			cfg, err := configuration.LoadConfig(t.Context(), nil)
			require.NoError(t, err)
			require.Equal(t, tt.expect().Fleet, cfg.Fleet)
			require.Equal(t, tt.expect().Settings, cfg.Settings)
		})
	}
}

// TestApplyCustomLogsPath exercises applyCustomLogsPath against a yaml config
// that has agent.logging.to_stderr: true (the shipped default). The "set" case
// simulates the user passing --path.logs on the CLI via the real flag mechanism.
func TestApplyCustomLogsPath(t *testing.T) {
	const customPath = "/tmp/custom-logs"

	// Mirrors the shipped default: to_stderr wins over to_files.
	toStderrYAML := []byte(`agent:
  logging:
    to_stderr: true
`)

	tests := map[string]struct {
		flagValue     string // non-empty: set --path.logs to this value via flag.CommandLine
		wantToStderr  bool
		wantToFiles   bool
		wantFilesPath string
	}{
		"--path.logs not set: config unchanged": {
			// Without --path.logs, applyCustomLogsPath is a no-op.
			// The raw loaded config has both ToStderr=true (from yaml) and
			// ToFiles=true (default); applyFlags in logp resolves the conflict
			// later when the logger is actually constructed.
			wantToStderr: true,
			wantToFiles:  true,
		},
		"--path.logs set: overrides yaml to_stderr, forces file output": {
			flagValue:     customPath,
			wantToStderr:  false,
			wantToFiles:   true,
			wantFilesPath: customPath,
		},
	}

	// Ensure the path.logs flag is registered before we try to Set it.
	paths.SetupFlags()

	origCfgDir := paths.Config()
	origLogsPath := paths.Logs()
	t.Cleanup(func() {
		paths.SetConfig(origCfgDir)
		paths.SetLogs(origLogsPath)
	})

	for name, tt := range tests {
		require.NoError(t, flag.CommandLine.Set("path.logs", "")) // reset flag before each test
		t.Run(name, func(t *testing.T) {
			if tt.flagValue != "" {
				require.NoError(t, flag.CommandLine.Set("path.logs", tt.flagValue))
			}

			dir := t.TempDir()
			paths.SetConfig(dir)
			require.NoError(t, os.WriteFile(filepath.Join(dir, paths.DefaultConfigName), toStderrYAML, 0o644))

			cfg, err := configuration.LoadConfig(t.Context(), nil)
			require.NoError(t, err)

			applyCustomLogsPath(cfg)

			assert.Equal(t, tt.wantToStderr, cfg.Settings.LoggingConfig.ToStderr)
			assert.Equal(t, tt.wantToFiles, cfg.Settings.LoggingConfig.ToFiles)
			assert.Equal(t, filepath.Join(paths.Home(), logger.DefaultLogDirectory, "events"), cfg.Settings.EventLoggingConfig.Files.Path)
			if tt.wantFilesPath != "" {
				assert.Equal(t, tt.wantFilesPath, cfg.Settings.LoggingConfig.Files.Path)
				assert.False(t, cfg.Settings.EventLoggingConfig.ToStderr)
				assert.True(t, cfg.Settings.EventLoggingConfig.ToFiles)
			} else {
				assert.Equal(t, paths.Top(), cfg.Settings.LoggingConfig.Files.Path)
			}
		})
	}
}

func TestTryDelayEnroll_ExitsOnCtxCancel(t *testing.T) {
	testutils.InitStorage(t)

	origCfgDir := paths.Config()
	t.Cleanup(func() { paths.SetConfig(origCfgDir) })
	paths.SetConfig(t.TempDir())

	// Reply with 503 on every request so the agent keeps retrying enrollment.
	gotRequest := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case gotRequest <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	enrollContents, err := yaml.Marshal(&enroll.EnrollOptions{
		URL:          server.URL,
		EnrollAPIKey: "fake-token",
		Insecure:     true,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(paths.AgentEnrollFile(), enrollContents, 0o600))

	log := logger.NewWithoutConfig("")
	cfg := configuration.DefaultConfiguration()

	ctx, cancel := context.WithCancel(t.Context())

	errCh := make(chan error, 1)
	go func() {
		_, err := tryDelayEnroll(ctx, log, cfg, nil)
		errCh <- err
	}()

	// Wait until the agent has actually started trying to enroll before
	// cancelling, so we know the retry loop is running.
	select {
	case <-gotRequest:
	case <-time.After(10 * time.Second):
		t.Fatal("server never received an enrollment request")
	}
	cancel()

	// After cancel, tryDelayEnroll should return promptly with context.Canceled.
	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		t.Fatal("tryDelayEnroll did not exit after ctx cancel")
	}
}
