// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/client/mocks"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func Test_CopyFile(t *testing.T) {
	l, _ := logger.New("test", false)
	tt := []struct {
		Name        string
		From        string
		To          string
		IgnoreErr   bool
		KeepOpen    bool
		ExpectedErr bool
	}{
		{
			"Existing, no onerr",
			filepath.Join(".", "test", "case1", "README.md"),
			filepath.Join(".", "test", "case1", "copy", "README.md"),
			false,
			false,
			false,
		},
		{
			"Existing but open",
			filepath.Join(".", "test", "case2", "README.md"),
			filepath.Join(".", "test", "case2", "copy", "README.md"),
			false,
			true,
			runtime.GOOS == "windows", // this fails only on,
		},
		{
			"Existing but open, ignore errors",
			filepath.Join(".", "test", "case3", "README.md"),
			filepath.Join(".", "test", "case3", "copy", "README.md"),
			true,
			true,
			false,
		},
		{
			"Not existing, accept errors",
			filepath.Join(".", "test", "case4", "README.md"),
			filepath.Join(".", "test", "case4", "copy", "README.md"),
			false,
			false,
			true,
		},
		{
			"Not existing, ignore errors",
			filepath.Join(".", "test", "case4", "README.md"),
			filepath.Join(".", "test", "case4", "copy", "README.md"),
			true,
			false,
			false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			defer func() {
				// cleanup
				_ = os.RemoveAll(filepath.Dir(tc.To))
			}()

			var fl *flock.Flock
			if tc.KeepOpen {
				// this uses syscalls to create inter-process lock
				fl = flock.New(tc.From)
				_, err := fl.TryLock()
				require.NoError(t, err)

				defer func() {
					require.NoError(t, fl.Unlock())
				}()

			}

			err := copyDir(l, tc.From, tc.To, tc.IgnoreErr)
			require.Equal(t, tc.ExpectedErr, err != nil, err)
		})
	}
}

func TestShutdownCallback(t *testing.T) {
	l, _ := logger.New("test", false)
	tmpDir, err := ioutil.TempDir("", "shutdown-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// make homepath agent consistent (in a form of elastic-agent-hash)
	homePath := filepath.Join(tmpDir, fmt.Sprintf("%s-%s", agentName, release.ShortCommit()))

	filename := "file.test"
	newCommit := "abc123"
	sourceVersion := "7.14.0"
	targetVersion := "7.15.0"

	content := []byte("content")
	newHome := strings.ReplaceAll(homePath, release.ShortCommit(), newCommit)
	sourceDir := filepath.Join(homePath, "run", "default", "process-"+sourceVersion)
	targetDir := filepath.Join(newHome, "run", "default", "process-"+targetVersion)

	require.NoError(t, os.MkdirAll(sourceDir, 0755))
	require.NoError(t, os.MkdirAll(targetDir, 0755))

	cb := shutdownCallback(l, homePath, sourceVersion, targetVersion, newCommit)

	oldFilename := filepath.Join(sourceDir, filename)
	err = ioutil.WriteFile(oldFilename, content, 0640)
	require.NoError(t, err, "preparing file failed")

	err = cb()
	require.NoError(t, err, "callback failed")

	newFilename := filepath.Join(targetDir, filename)
	newContent, err := ioutil.ReadFile(newFilename)
	require.NoError(t, err, "reading file failed")
	require.Equal(t, content, newContent, "contents are not equal")
}

func TestIsInProgress(t *testing.T) {
	tests := map[string]struct {
		state              cproto.State
		stateErr           string
		watcherPIDsFetcher func() ([]int, error)

		expected    bool
		expectedErr string
	}{
		"state_error": {
			state:              cproto.State_STARTING,
			stateErr:           "some error",
			watcherPIDsFetcher: func() ([]int, error) { return nil, nil },

			expected:    false,
			expectedErr: "failed to get agent state: some error",
		},
		"state_upgrading": {
			state:              cproto.State_UPGRADING,
			stateErr:           "",
			watcherPIDsFetcher: func() ([]int, error) { return nil, nil },

			expected:    true,
			expectedErr: "",
		},
		"state_healthy_no_watcher": {
			state:              cproto.State_HEALTHY,
			stateErr:           "",
			watcherPIDsFetcher: func() ([]int, error) { return []int{}, nil },

			expected:    false,
			expectedErr: "",
		},
		"state_healthy_with_watcher": {
			state:              cproto.State_HEALTHY,
			stateErr:           "",
			watcherPIDsFetcher: func() ([]int, error) { return []int{9999}, nil },

			expected:    true,
			expectedErr: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			// Expect client.State() call to be made only if no Upgrade Watcher PIDs
			// are returned (i.e. no Upgrade Watcher is found to be running).
			mc := mocks.NewClient(t)
			if test.watcherPIDsFetcher != nil {
				pids, _ := test.watcherPIDsFetcher()
				if len(pids) == 0 {
					if test.stateErr != "" {
						mc.EXPECT().State(context.Background()).Return(nil, errors.New(test.stateErr)).Once()
					} else {
						mc.EXPECT().State(context.Background()).Return(&client.AgentState{State: test.state}, nil).Once()
					}
				}
			}

			inProgress, err := IsInProgress(mc, test.watcherPIDsFetcher)
			if test.expectedErr != "" {
				require.Equal(t, test.expectedErr, err.Error())
			} else {
				require.Equal(t, test.expected, inProgress)
			}
		})
	}
}

func TestUpgraderReload(t *testing.T) {
	defaultCfg := artifact.DefaultConfig()
	tcs := []struct {
		name      string
		sourceURL string
		proxyURL  string
		cfg       string
	}{
		{
			name:      "proxy_url is applied",
			sourceURL: defaultCfg.SourceURI,
			proxyURL:  "http://someBrokenURL/",
			cfg: `
agent.download:
  proxy_url: http://someBrokenURL/
`,
		},
		{
			name:      "source_uri has precedence over sourceURI",
			sourceURL: "https://this.sourceURI.co/downloads/beats/",
			cfg: `
agent.download:
  source_uri: "https://this.sourceURI.co/downloads/beats/"
  sourceURI: "https://NOT.sourceURI.co/downloads/beats/"
`}, {
			name:      "only sourceURI",
			sourceURL: "https://this.sourceURI.co/downloads/beats/",
			cfg: `
agent.download:
  sourceURI: "https://this.sourceURI.co/downloads/beats/"
`}, {
			name:      "only source_uri",
			sourceURL: "https://this.sourceURI.co/downloads/beats/",
			cfg: `
agent.download:
  source_uri: "https://this.sourceURI.co/downloads/beats/"
`},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			log, _ := logger.NewTesting("")

			u := Upgrader{
				log:      log,
				settings: artifact.DefaultConfig(),
			}

			cfg, err := config.NewConfigFrom(tc.cfg)
			require.NoError(t, err, "failed to create new config")

			err = u.Reload(cfg)
			require.NoError(t, err, "error reloading config")

			assert.Equal(t, tc.sourceURL, u.settings.SourceURI)
			if tc.proxyURL != "" {
				require.NotNilf(t, u.settings.Proxy.URL,
					"ProxyURI should not be nil, want %s", tc.proxyURL)
				assert.Equal(t, tc.proxyURL, u.settings.Proxy.URL.String())
			}
		})
	}
}
