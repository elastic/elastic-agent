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

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
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
			require.Equal(t, tc.ExpectedErr, err != nil)
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

type mockClient struct {
	stateErr string
	state    cproto.State
}

func (mc *mockClient) Connect(ctx context.Context) error { return nil }
func (mc *mockClient) Disconnect()                       {}
func (mc *mockClient) Version(ctx context.Context) (client.Version, error) {
	return client.Version{}, nil
}
func (mc *mockClient) State(ctx context.Context) (*client.AgentState, error) {
	if mc.stateErr != "" {
		return nil, errors.New(mc.stateErr)
	}

	return &client.AgentState{State: mc.state}, nil
}
func (mc *mockClient) StateWatch(ctx context.Context) (client.ClientStateWatch, error) {
	return nil, nil
}
func (mc *mockClient) Restart(ctx context.Context) error { return nil }
func (mc *mockClient) Upgrade(ctx context.Context, version string, sourceURI string, skipVerify bool, skipDefaultPgp bool, pgpBytes ...string) (string, error) {
	return "", nil
}
func (mc *mockClient) DiagnosticAgent(ctx context.Context, additionalDiags []client.AdditionalMetrics) ([]client.DiagnosticFileResult, error) {
	return nil, nil
}
func (mc *mockClient) DiagnosticUnits(ctx context.Context, units ...client.DiagnosticUnitRequest) ([]client.DiagnosticUnitResult, error) {
	return nil, nil
}
func (mc *mockClient) DiagnosticComponents(ctx context.Context, additionalDiags []client.AdditionalMetrics, components ...client.DiagnosticComponentRequest) ([]client.DiagnosticComponentResult, error) {
	return nil, nil
}
func (mc *mockClient) Configure(ctx context.Context, config string) error { return nil }

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
			mc := mockClient{state: test.state, stateErr: test.stateErr}
			inProgress, err := IsInProgress(&mc, test.watcherPIDsFetcher)
			if test.expectedErr != "" {
				require.Equal(t, test.expectedErr, err.Error())
			} else {
				require.Equal(t, test.expected, inProgress)
			}
		})
	}
}
