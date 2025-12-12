// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/version"
	agtversion "github.com/elastic/elastic-agent/version"
)

func TestManualRollback(t *testing.T) {
	const updatemarkerwatching456NoRollbackAvailable = `
   version: 4.5.6
   hash: newver
   versioned_home: data/elastic-agent-4.5.6-newver
   updated_on: 2025-07-11T10:11:12.131415Z
   prev_version: 1.2.3
   prev_hash: oldver
   prev_versioned_home: data/elastic-agent-1.2.3-oldver
   acked: false
   action: null
   details:
       target_version: 4.5.6
       state: UPG_WATCHING
       metadata:
           retry_until: null
   `
	const updatemarkerwatching456 = `
   version: 4.5.6
   hash: newver
   versioned_home: data/elastic-agent-4.5.6-newver
   updated_on: 2025-07-11T10:11:12.131415Z
   prev_version: 1.2.3
   prev_hash: oldver
   prev_versioned_home: data/elastic-agent-1.2.3-oldver
   acked: false
   action: null
   details:
       target_version: 4.5.6
       state: UPG_WATCHING
       metadata:
           retry_until: null
   desired_outcome: UPGRADE
   rollbacks_available:
     "data/elastic-agent-1.2.3-oldver":
       version: 1.2.3
       valid_until: 2025-07-18T10:11:12.131415Z
   `

	parsed123Version, err := version.ParseVersion("1.2.3")
	require.NoError(t, err)
	parsed456Version, err := version.ParseVersion("4.5.6")
	require.NoError(t, err)

	agentInstall123 := agentInstall{
		parsedVersion: parsed123Version,
		version:       "1.2.3",
		hash:          "oldver",
		versionedHome: "data/elastic-agent-1.2.3-oldver",
	}

	agentInstall456 := agentInstall{
		parsedVersion: parsed456Version,
		version:       "4.5.6",
		hash:          "newver",
		versionedHome: "data/elastic-agent-4.5.6-newver",
	}

	agentInstallCurrent := agentInstall{
		parsedVersion: agtversion.GetParsedAgentPackageVersion(),
		version:       release.VersionWithSnapshot(),
		hash:          release.Commit(),
		// Versioned home should contain the version but since the path does not really exist we fallback to the legacy format with just the hash
		// versionedHome: filepath.Join("data", fmt.Sprintf("elastic-agent-%s-%s", release.VersionWithSnapshot(), release.ShortCommit())),
		versionedHome: filepath.Join("data", fmt.Sprintf("elastic-agent-%s", release.ShortCommit())),
	}

	// this is the updated_on timestamp in the example
	nowBeforeTTL, err := time.Parse(time.RFC3339, `2025-07-11T10:11:12Z`)
	require.NoError(t, err, "error parsing nowBeforeTTL")

	// the update marker yaml assume 7d TLL for rollbacks, let's make an extra day pass
	nowAfterTTL := nowBeforeTTL.Add(8 * 24 * time.Hour)

	// save the current timestamp, useful for TTL-based testing
	aMomentInTime := time.Now()
	aMomentTomorrow := aMomentInTime.Add(24 * time.Hour)
	aMomentAgo := aMomentInTime.Add(-1 * time.Second)

	type setupF func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource)
	type postRollbackAssertionsF func(t *testing.T, topDir string)
	type testcase struct {
		name              string
		setup             setupF
		artifactSettings  *artifact.Config
		upgradeSettings   *configuration.UpgradeConfig
		now               time.Time
		version           string
		wantErr           assert.ErrorAssertionFunc
		additionalAsserts postRollbackAssertionsF
	}

	testcases := []testcase{
		{
			name: "no rollback version - rollback fails",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				//do not setup anything here, let the rollback fail
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings:  configuration.DefaultUpgradeConfig(),
			version:          "",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrEmptyRollbackVersion)
			},
			additionalAsserts: nil,
		},
		{
			name: "no update marker - rollback fails",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				//do not setup anything here, let the rollback fail
				rollbacksSource.EXPECT().Get().Return(nil, nil)
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings:  configuration.DefaultUpgradeConfig(),
			version:          "1.2.3",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrNoRollbacksAvailable)
			},
			additionalAsserts: nil,
		},
		{
			name: "update marker is malformed - rollback fails",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				err := os.WriteFile(markerFilePath(paths.DataFrom(topDir)), []byte("this is not a proper YAML file"), 0600)
				require.NoError(t, err, "error setting up update marker")
				locker := filelock.NewAppLocker(topDir, "watcher.lock")
				err = locker.TryLock()
				require.NoError(t, err, "error locking initial watcher AppLocker")
				// there's no takeover watcher so no expectation on that or InvokeWatcher
				t.Cleanup(func() {
					unlockErr := locker.Unlock()
					assert.NoError(t, unlockErr, "error unlocking initial watcher AppLocker")
				})
			},
			artifactSettings:  artifact.DefaultConfig(),
			upgradeSettings:   configuration.DefaultUpgradeConfig(),
			version:           "1.2.3",
			wantErr:           assert.Error,
			additionalAsserts: nil,
		},
		{
			name: "update marker ok but rollback available is empty - error",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				err := os.WriteFile(markerFilePath(paths.DataFrom(topDir)), []byte(updatemarkerwatching456NoRollbackAvailable), 0600)
				require.NoError(t, err, "error setting up update marker")
				locker := filelock.NewAppLocker(topDir, "watcher.lock")
				err = locker.TryLock()
				require.NoError(t, err, "error locking initial watcher AppLocker")
				watcherHelper.EXPECT().TakeOverWatcher(t.Context(), mock.Anything, topDir).Return(locker, nil)
				newerWatcherExecutable := filepath.Join(topDir, "data", "elastic-agent-4.5.6-newver", "elastic-agent")
				watcherHelper.EXPECT().SelectWatcherExecutable(topDir, agentInstall123, agentInstall456).Return(newerWatcherExecutable)
				watcherHelper.EXPECT().InvokeWatcher(mock.Anything, newerWatcherExecutable).Return(&exec.Cmd{Path: newerWatcherExecutable, Args: []string{"watch", "for realsies"}}, nil)
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings:  configuration.DefaultUpgradeConfig(),
			version:          "2.3.4-unknown",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrNoRollbacksAvailable)
			},
			additionalAsserts: func(t *testing.T, topDir string) {
				// marker should be untouched
				filePath := markerFilePath(paths.DataFrom(topDir))
				require.FileExists(t, filePath)
				markerFileBytes, readMarkerErr := os.ReadFile(filePath)
				require.NoError(t, readMarkerErr)

				assert.YAMLEq(t, updatemarkerwatching456NoRollbackAvailable, string(markerFileBytes), "update marker should be untouched")
			},
		},
		{
			name: "update marker ok but version is not available for rollback - error",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				err := os.WriteFile(markerFilePath(paths.DataFrom(topDir)), []byte(updatemarkerwatching456), 0600)
				require.NoError(t, err, "error setting up update marker")
				locker := filelock.NewAppLocker(topDir, "watcher.lock")
				err = locker.TryLock()
				require.NoError(t, err, "error locking initial watcher AppLocker")
				watcherHelper.EXPECT().TakeOverWatcher(t.Context(), mock.Anything, topDir).Return(locker, nil)
				newerWatcherExecutable := filepath.Join(topDir, "data", "elastic-agent-4.5.6-newver", "elastic-agent")
				watcherHelper.EXPECT().SelectWatcherExecutable(topDir, agentInstall123, agentInstall456).Return(newerWatcherExecutable)
				watcherHelper.EXPECT().InvokeWatcher(mock.Anything, newerWatcherExecutable).Return(&exec.Cmd{Path: newerWatcherExecutable, Args: []string{"watch", "for realsies"}}, nil)
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings:  configuration.DefaultUpgradeConfig(),
			version:          "2.3.4-unknown",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrNoRollbacksAvailable)
			},
			additionalAsserts: func(t *testing.T, topDir string) {
				// marker should be untouched
				filePath := markerFilePath(paths.DataFrom(topDir))
				require.FileExists(t, filePath)
				markerFileBytes, readMarkerErr := os.ReadFile(filePath)
				require.NoError(t, readMarkerErr)

				assert.YAMLEq(t, updatemarkerwatching456, string(markerFileBytes), "update marker should be untouched")
			},
		},
		{
			name: "update marker ok but rollback is expired - error",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				err := os.WriteFile(markerFilePath(paths.DataFrom(topDir)), []byte(updatemarkerwatching456), 0600)
				require.NoError(t, err, "error setting up update marker")
				locker := filelock.NewAppLocker(topDir, "watcher.lock")
				err = locker.TryLock()
				require.NoError(t, err, "error locking initial watcher AppLocker")
				watcherHelper.EXPECT().TakeOverWatcher(t.Context(), mock.Anything, topDir).Return(locker, nil)
				newerWatcherExecutable := filepath.Join(topDir, "data", "elastic-agent-4.5.6-newver", "elastic-agent")
				watcherHelper.EXPECT().SelectWatcherExecutable(topDir, agentInstall123, agentInstall456).Return(newerWatcherExecutable)
				watcherHelper.EXPECT().InvokeWatcher(mock.Anything, newerWatcherExecutable).Return(&exec.Cmd{Path: newerWatcherExecutable, Args: []string{"watch", "for realsies"}}, nil)
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings:  configuration.DefaultUpgradeConfig(),
			now:              nowAfterTTL,
			version:          "1.2.3",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrNoRollbacksAvailable)
			},
			additionalAsserts: func(t *testing.T, topDir string) {
				// marker should be untouched
				filePath := markerFilePath(paths.DataFrom(topDir))
				require.FileExists(t, filePath)
				markerFileBytes, readMarkerErr := os.ReadFile(filePath)
				require.NoError(t, readMarkerErr)

				assert.YAMLEq(t, updatemarkerwatching456, string(markerFileBytes), "update marker should be untouched")
			},
		},
		{
			name: "update marker ok, rollback valid, invoking watcher fails - error",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				err := os.WriteFile(markerFilePath(paths.DataFrom(topDir)), []byte(updatemarkerwatching456), 0600)
				require.NoError(t, err, "error setting up update marker")
				locker := filelock.NewAppLocker(topDir, "watcher.lock")
				err = locker.TryLock()
				require.NoError(t, err, "error locking initial watcher AppLocker")
				watcherHelper.EXPECT().TakeOverWatcher(t.Context(), mock.Anything, topDir).Return(locker, nil)
				newerWatcherExecutable := filepath.Join(topDir, "data", "elastic-agent-4.5.6-newver", "elastic-agent")
				watcherHelper.EXPECT().SelectWatcherExecutable(topDir, agentInstall123, agentInstall456).Return(newerWatcherExecutable)
				// invoking watcher rollback fails
				watcherHelper.EXPECT().InvokeWatcher(mock.Anything, newerWatcherExecutable, "--rollback", agentInstall123.versionedHome).Return(nil, errors.New("error invoking watcher"))
				// Expect watch to be resumed
				watcherHelper.EXPECT().InvokeWatcher(mock.Anything, newerWatcherExecutable).Return(&exec.Cmd{Path: newerWatcherExecutable, Args: []string{"watch", "for realsies"}}, nil)
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings:  configuration.DefaultUpgradeConfig(),
			now:              nowBeforeTTL,
			version:          "1.2.3",
			wantErr:          assert.Error,
			additionalAsserts: func(t *testing.T, topDir string) {
				// marker should be untouched
				filePath := markerFilePath(paths.DataFrom(topDir))
				require.FileExists(t, filePath)
				markerFileBytes, readMarkerErr := os.ReadFile(filePath)
				require.NoError(t, readMarkerErr)

				assert.YAMLEq(t, updatemarkerwatching456, string(markerFileBytes), "update marker should be untouched")
			},
		},
		{
			name: "update marker ok - takeover watcher, persist rollback and restart most recent watcher",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				err := os.WriteFile(markerFilePath(paths.DataFrom(topDir)), []byte(updatemarkerwatching456), 0600)
				require.NoError(t, err, "error setting up update marker")
				locker := filelock.NewAppLocker(topDir, "watcher.lock")
				err = locker.TryLock()
				require.NoError(t, err, "error locking initial watcher AppLocker")
				watcherHelper.EXPECT().TakeOverWatcher(t.Context(), mock.Anything, topDir).Return(locker, nil)
				newerWatcherExecutable := filepath.Join(topDir, "data", "elastic-agent-4.5.6-newver", "elastic-agent")
				watcherHelper.EXPECT().SelectWatcherExecutable(topDir, agentInstall123, agentInstall456).Return(newerWatcherExecutable)
				watcherHelper.EXPECT().
					InvokeWatcher(mock.Anything, newerWatcherExecutable, "--rollback", "data/elastic-agent-1.2.3-oldver").
					Return(&exec.Cmd{Path: newerWatcherExecutable, Args: []string{"watch", "for rollbacksies"}, Process: &os.Process{Pid: 123}}, nil)
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings:  configuration.DefaultUpgradeConfig(),
			now:              nowBeforeTTL,
			version:          "1.2.3",
			wantErr:          assert.NoError,
			additionalAsserts: func(t *testing.T, topDir string) {
				marker, loadMarkerErr := LoadMarker(paths.DataFrom(topDir))
				require.NoError(t, loadMarkerErr, "error loading marker")
				require.NotNil(t, marker, "marker is nil")

				require.NotNil(t, marker.Details)
				assert.NotEmpty(t, marker.RollbacksAvailable)
			},
		},
		{
			name: "no update marker, available install for rollback with valid TTL - rollback",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				rollbacksSource.EXPECT().Get().Return(map[string]ttl.TTLMarker{
					"data/elastic-agent-1.2.3-oldver": {
						Version:    "1.2.3",
						Hash:       "oldver",
						ValidUntil: aMomentTomorrow,
					},
				}, nil)
				newerWatcherExecutable := filepath.Join(topDir, "data", fmt.Sprintf("elastic-agent-%s-%s", release.VersionWithSnapshot(), release.ShortCommit()), "elastic-agent")
				watcherHelper.EXPECT().SelectWatcherExecutable(topDir, agentInstall123, agentInstallCurrent).Return(newerWatcherExecutable)
				watcherHelper.EXPECT().InvokeWatcher(mock.Anything, newerWatcherExecutable, "--rollback", "data/elastic-agent-1.2.3-oldver").
					Return(&exec.Cmd{Path: newerWatcherExecutable, Args: []string{"watch", "for rollbacksies"}, Process: &os.Process{Pid: 123}}, nil)
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings: &configuration.UpgradeConfig{
				Rollback: &configuration.UpgradeRollbackConfig{
					Window: 24 * time.Hour,
				},
			},
			now:     aMomentInTime,
			version: "1.2.3",
			wantErr: assert.NoError,
			additionalAsserts: func(t *testing.T, topDir string) {
				actualMarkerFilePath := filepath.Join(topDir, "data", markerFilename)
				require.FileExists(t, actualMarkerFilePath, "marker file must have been created")
				actualMarkerFileBytes, errReadMarkerFile := os.ReadFile(actualMarkerFilePath)
				require.NoError(t, errReadMarkerFile, "marker file should be readable")

				expectedUpdateMarker := &UpdateMarker{
					Version:           release.VersionWithSnapshot(),
					Hash:              release.Commit(),
					VersionedHome:     filepath.Join("data", fmt.Sprintf("elastic-agent-%s", release.ShortCommit())),
					UpdatedOn:         aMomentInTime,
					PrevVersion:       "1.2.3",
					PrevHash:          "oldver",
					PrevVersionedHome: "data/elastic-agent-1.2.3-oldver",
					Details: &details.Details{
						TargetVersion: release.VersionWithSnapshot(),
						State:         details.StateRequested,
					},
					RollbacksAvailable: nil,
				}

				expectedMarkerBytes, err := yaml.Marshal(newMarkerSerializer(expectedUpdateMarker))
				require.NoError(t, err, "error marshalling expected update marker")
				require.YAMLEq(t, string(expectedMarkerBytes), string(actualMarkerFileBytes))
			},
		},
		{
			name: "no update marker, available install for rollback with expired TTL - error",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				rollbacksSource.EXPECT().Get().Return(
					map[string]ttl.TTLMarker{
						"data/elastic-agent-1.2.3-oldver": {
							Version:    "1.2.3",
							Hash:       "oldver",
							ValidUntil: aMomentAgo,
						},
					},
					nil)
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings: &configuration.UpgradeConfig{
				Rollback: &configuration.UpgradeRollbackConfig{
					Window: 24 * time.Hour,
				},
			},
			now:     aMomentInTime,
			version: "1.2.3",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrNoRollbacksAvailable, i...)
			},
			additionalAsserts: func(t *testing.T, topDir string) {
				actualMarkerFilePath := filepath.Join(topDir, "data", markerFilename)
				require.NoFileExists(t, actualMarkerFilePath, "marker file must not be created")

			},
		},
		{
			name: "no update marker, no available install for the version - error",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				rollbacksSource.EXPECT().Get().Return(
					map[string]ttl.TTLMarker{
						"data/elastic-agent-1.2.3-oldver": {
							Version:    "1.2.3",
							Hash:       "oldver",
							ValidUntil: aMomentTomorrow,
						},
					},
					nil)
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings: &configuration.UpgradeConfig{
				Rollback: &configuration.UpgradeRollbackConfig{
					Window: 24 * time.Hour,
				},
			},
			now:     aMomentInTime,
			version: "6.6.6",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrNoRollbacksAvailable, i...)
			},
			additionalAsserts: func(t *testing.T, topDir string) {
				actualMarkerFilePath := filepath.Join(topDir, "data", markerFilename)
				require.NoFileExists(t, actualMarkerFilePath, "marker file must not be created")

			},
		},
		{
			name: "no update marker, error retrieving agent installs",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				rollbacksSource.EXPECT().Get().Return(nil, errors.New("error retrieving agent rollbacks"))
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings: &configuration.UpgradeConfig{
				Rollback: &configuration.UpgradeRollbackConfig{
					Window: 24 * time.Hour,
				},
			},
			now:     aMomentInTime,
			version: "1.2.3",
			wantErr: assert.Error,
		},
		{
			name: "no update marker, invoking watcher fails - error",
			setup: func(t *testing.T, topDir string, agent *info.MockAgent, watcherHelper *MockWatcherHelper, rollbacksSource *mockAvailableRollbacksSource) {
				rollbacksSource.EXPECT().Get().Return(
					map[string]ttl.TTLMarker{
						"data/elastic-agent-1.2.3-oldver": {
							Version:    "1.2.3",
							Hash:       "oldver",
							ValidUntil: aMomentTomorrow,
						},
					},
					nil,
				)
				newerWatcherExecutable := filepath.Join(topDir, "data", fmt.Sprintf("elastic-agent-%s-%s", release.VersionWithSnapshot(), release.ShortCommit()), "elastic-agent")
				watcherHelper.EXPECT().SelectWatcherExecutable(topDir, agentInstall123, agentInstallCurrent).Return(newerWatcherExecutable)
				watcherHelper.EXPECT().InvokeWatcher(mock.Anything, newerWatcherExecutable, "--rollback", "data/elastic-agent-1.2.3-oldver").
					Return(nil, errors.New("error invoking watcher"))
			},
			artifactSettings: artifact.DefaultConfig(),
			upgradeSettings: &configuration.UpgradeConfig{
				Rollback: &configuration.UpgradeRollbackConfig{
					Window: 24 * time.Hour,
				},
			},
			now:     aMomentInTime,
			version: "1.2.3",
			wantErr: assert.Error,
			additionalAsserts: func(t *testing.T, topDir string) {
				actualMarkerFilePath := filepath.Join(topDir, "data", markerFilename)
				require.NoFileExists(t, actualMarkerFilePath, "marker file must have been created")
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			log, _ := loggertest.New(t.Name())
			mockAgentInfo := info.NewMockAgent(t)
			mockWatcherHelper := NewMockWatcherHelper(t)
			mockRollbacksSource := newMockAvailableRollbacksSource(t)
			topDir := t.TempDir()
			err := os.MkdirAll(paths.DataFrom(topDir), 0777)
			require.NoError(t, err, "error creating data directory in topDir %q", topDir)

			if tc.setup != nil {
				tc.setup(t, topDir, mockAgentInfo, mockWatcherHelper, mockRollbacksSource)
			}

			upgrader, err := NewUpgrader(log, tc.artifactSettings, tc.upgradeSettings, mockAgentInfo, mockWatcherHelper, mockRollbacksSource)
			require.NoError(t, err, "error instantiating upgrader")
			_, err = upgrader.rollbackToPreviousVersion(t.Context(), topDir, tc.now, tc.version, nil)
			tc.wantErr(t, err, "unexpected error returned by rollbackToPreviousVersion()")
			if tc.additionalAsserts != nil {
				tc.additionalAsserts(t, topDir)
			}
		})
	}
}

func TestCleanAvailableRollbacks(t *testing.T) {
	// various timestamps
	now := time.Now().UTC().Truncate(time.Millisecond)
	oneHourAgo := now.Add(-1 * time.Hour)
	oneHourFromNow := now.Add(1 * time.Hour)

	// Convenience test agent version structs
	v123Expired := testAgentVersion{
		version: "1.2.3",
		hash:    "expire",
	}
	v456Valid := testAgentVersion{
		version: "4.5.6",
		hash:    "valid1",
	}
	v789Actual := testAgentVersion{
		version: "7.8.9",
		hash:    "actual",
	}

	type args struct {
		currentHomeRelPath string
		filter             RollbackCleanupFilter
	}
	tests := []struct {
		name                  string
		setup                 func(t *testing.T, log *logger.Logger, topDir string, rollbackSource *mockAvailableRollbacksSource)
		args                  args
		want                  map[string]ttl.TTLMarker
		wantErr               assert.ErrorAssertionFunc
		postCleanupAssertions func(t *testing.T, topDir string)
	}{
		{
			name: "Clear all available rollbacks regardless of ttl when using CleanupAllRollbacks",
			setup: func(t *testing.T, log *logger.Logger, topDir string, rollbackSource *mockAvailableRollbacksSource) {
				rollbackSource.EXPECT().Get().Return(map[string]ttl.TTLMarker{
					filepath.Join("data", "elastic-agent-1.2.3-expire"): {
						Version:    "1.2.3",
						Hash:       "expire",
						ValidUntil: oneHourAgo, // expired 1 hour ago
					},
					filepath.Join("data", "elastic-agent-4.5.6-valid1"): {
						Version:    "4.5.6",
						Hash:       "valid1",
						ValidUntil: oneHourFromNow, // still valid
					},
				}, nil)
				rollbackSource.EXPECT().Remove(filepath.Join("data", "elastic-agent-1.2.3-expire")).Return(nil)
				rollbackSource.EXPECT().Remove(filepath.Join("data", "elastic-agent-4.5.6-valid1")).Return(nil)

				// setup the fake agent installations
				setupAgents(t, log, topDir, setupAgentInstallations{
					installedAgents: []testAgentInstall{
						{
							version:          v123Expired,
							useVersionInPath: true,
						},
						{
							version:          v456Valid,
							useVersionInPath: true,
						},
						{
							version:          v789Actual,
							useVersionInPath: true,
						},
					},
					upgradeFrom:  testAgentVersion{},
					upgradeTo:    testAgentVersion{},
					currentAgent: v789Actual,
				},
					false,
				)
			},
			args: args{
				currentHomeRelPath: filepath.Join("data", "elastic-agent-7.8.9-actual"),
				filter:             CleanupAllRollbacks,
			},
			want:    map[string]ttl.TTLMarker{},
			wantErr: assert.NoError,
			postCleanupAssertions: func(t *testing.T, topDir string) {
				assert.NoDirExists(t, filepath.Join(topDir, "data", "elastic-agent-1.2.3-expire"), "expired rollback should have been removed")
				assert.NoDirExists(t, filepath.Join(topDir, "data", "elastic-agent-4.5.6-valid1"), "valid rollback should have been removed")
				assert.DirExists(t, filepath.Join(topDir, "data", "elastic-agent-7.8.9-actual"), "current agent install should have been preserved")
			},
		},
		{
			name: "Clear expired available rollbacks when using CleanupExpiredRollbacks",
			setup: func(t *testing.T, log *logger.Logger, topDir string, rollbackSource *mockAvailableRollbacksSource) {
				rollbackSource.EXPECT().Get().Return(map[string]ttl.TTLMarker{
					filepath.Join("data", "elastic-agent-1.2.3-expire"): {
						Version:    "1.2.3",
						Hash:       "expire",
						ValidUntil: oneHourAgo, // expired 1 hour ago
					},
					filepath.Join("data", "elastic-agent-4.5.6-valid1"): {
						Version:    "4.5.6",
						Hash:       "valid1",
						ValidUntil: oneHourFromNow, // still valid
					},
				}, nil)

				rollbackSource.EXPECT().Remove(filepath.Join("data", "elastic-agent-1.2.3-expire")).Return(nil)

				// setup the fake agent installations
				setupAgents(t, log, topDir, setupAgentInstallations{
					installedAgents: []testAgentInstall{
						{
							version:          v123Expired,
							useVersionInPath: true,
						},
						{
							version:          v456Valid,
							useVersionInPath: true,
						},
						{
							version:          v789Actual,
							useVersionInPath: true,
						},
					},
					upgradeFrom:  testAgentVersion{},
					upgradeTo:    testAgentVersion{},
					currentAgent: v789Actual,
				},
					false,
				)
			},
			args: args{
				currentHomeRelPath: filepath.Join("data", "elastic-agent-7.8.9-actual"),
				filter:             CleanupExpiredRollbacks,
			},
			want: map[string]ttl.TTLMarker{
				filepath.Join("data", "elastic-agent-4.5.6-valid1"): {
					Version:    "4.5.6",
					Hash:       "valid1",
					ValidUntil: oneHourFromNow, // still valid
				},
			},
			wantErr: assert.NoError,
			postCleanupAssertions: func(t *testing.T, topDir string) {
				assert.NoDirExists(t, filepath.Join(topDir, "data", "elastic-agent-1.2.3-expire"), "expired rollback should have been removed")
				assert.DirExists(t, filepath.Join(topDir, "data", "elastic-agent-4.5.6-valid1"), "valid rollback should have not been removed")
				assert.DirExists(t, filepath.Join(topDir, "data", "elastic-agent-7.8.9-actual"), "current agent install should have been preserved")
			},
		},
		{
			name: "Current install should be preserved when using CleanupAllRollbacks even if marked as an available rollback",
			setup: func(t *testing.T, log *logger.Logger, topDir string, rollbackSource *mockAvailableRollbacksSource) {
				rollbackSource.EXPECT().Get().Return(map[string]ttl.TTLMarker{
					filepath.Join("data", "elastic-agent-7.8.9-actual"): {
						Version:    "7.8.9",
						Hash:       "actual",
						ValidUntil: oneHourAgo, // expired 1 hour ago
					},
				}, nil)

				// setup the fake agent installations
				setupAgents(t, log, topDir, setupAgentInstallations{
					installedAgents: []testAgentInstall{
						{
							version:          v789Actual,
							useVersionInPath: true,
						},
					},
					upgradeFrom:  testAgentVersion{},
					upgradeTo:    testAgentVersion{},
					currentAgent: v789Actual,
				},
					false,
				)
			},
			args: args{
				currentHomeRelPath: filepath.Join("data", "elastic-agent-7.8.9-actual"),
				filter:             CleanupAllRollbacks,
			},
			want:    map[string]ttl.TTLMarker{},
			wantErr: assert.NoError,
			postCleanupAssertions: func(t *testing.T, topDir string) {
				assert.DirExists(t, filepath.Join(topDir, "data", "elastic-agent-7.8.9-actual"), "current agent install should have been preserved")
			},
		},
		{
			name: "Current install should be preserved when using CleanupExpiredRollbacks even if marked as an available rollback",
			setup: func(t *testing.T, log *logger.Logger, topDir string, rollbackSource *mockAvailableRollbacksSource) {
				rollbackSource.EXPECT().Get().Return(map[string]ttl.TTLMarker{
					filepath.Join("data", "elastic-agent-7.8.9-actual"): {
						Version:    "7.8.9",
						Hash:       "actual",
						ValidUntil: oneHourAgo, // expired 1 hour ago
					},
				}, nil)

				// setup the fake agent installations
				setupAgents(t, log, topDir, setupAgentInstallations{
					installedAgents: []testAgentInstall{
						{
							version:          v789Actual,
							useVersionInPath: true,
						},
					},
					upgradeFrom:  testAgentVersion{},
					upgradeTo:    testAgentVersion{},
					currentAgent: v789Actual,
				},
					false,
				)
			},
			args: args{
				currentHomeRelPath: filepath.Join("data", "elastic-agent-7.8.9-actual"),
				filter:             CleanupExpiredRollbacks,
			},
			want:    map[string]ttl.TTLMarker{},
			wantErr: assert.NoError,
			postCleanupAssertions: func(t *testing.T, topDir string) {
				assert.DirExists(t, filepath.Join(topDir, "data", "elastic-agent-7.8.9-actual"), "current agent install should have been preserved")
			},
		},
		{
			name: "Preserve available rollbacks if involved in an active upgrade",
			setup: func(t *testing.T, log *logger.Logger, topDir string, rollbackSource *mockAvailableRollbacksSource) {

				rollbackSource.EXPECT().Get().Return(map[string]ttl.TTLMarker{
					filepath.Join("data", "elastic-agent-1.2.3-oldver"): {
						Version:    "1.2.3",
						Hash:       "oldver",
						ValidUntil: oneHourAgo, // expired 1 hour ago
					},
				}, nil)

				fromVersion := testAgentVersion{
					version: "1.2.3",
					hash:    "oldver",
				}

				// setup the fake agent installations
				toVersion := testAgentVersion{
					version: "4.5.6",
					hash:    "newver",
				}
				setupAgents(t, log, topDir, setupAgentInstallations{
					installedAgents: []testAgentInstall{
						{
							version:          fromVersion,
							useVersionInPath: true,
						},
						{
							version:          toVersion,
							useVersionInPath: true,
						},
					},
					upgradeFrom:  fromVersion,
					upgradeTo:    toVersion,
					currentAgent: toVersion,
				}, true)
			},
			args: args{
				currentHomeRelPath: filepath.Join("data", "elastic-agent-4.5.6-newver"),
				filter: PreserveActiveUpgradeVersions(&UpdateMarker{
					Version:            "4.5.6",
					Hash:               "newver",
					VersionedHome:      filepath.Join("data", "elastic-agent-4.5.6-newver"),
					UpdatedOn:          now,
					PrevVersion:        "1.2.3",
					PrevHash:           "oldver",
					PrevVersionedHome:  filepath.Join("data", "elastic-agent-1.2.3-oldver"),
					Acked:              false,
					Action:             nil,
					Details:            nil,
					RollbacksAvailable: nil,
				},
					CleanupExpiredRollbacks,
				),
			},
			want: map[string]ttl.TTLMarker{
				filepath.Join("data", "elastic-agent-1.2.3-oldver"): {
					Version:    "1.2.3",
					Hash:       "oldver",
					ValidUntil: now.Add(-1 * time.Hour),
				},
			},
			wantErr:               assert.NoError,
			postCleanupAssertions: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, _ := loggertest.New(t.Name())
			topDir := t.TempDir()
			err := os.MkdirAll(filepath.Join(topDir, "data"), 0755)
			require.NoError(t, err, "error creating data directory in topDir %q", topDir)
			mockRollbacksSource := newMockAvailableRollbacksSource(t)

			tt.setup(t, log, topDir, mockRollbacksSource)
			got, err := CleanAvailableRollbacks(log, mockRollbacksSource, topDir, tt.args.currentHomeRelPath, time.Now(), tt.args.filter)
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, got)
			if tt.postCleanupAssertions != nil {
				tt.postCleanupAssertions(t, topDir)
			}
		})
	}
}

func TestPerformScheduledCleanup(t *testing.T) {

	now := time.Now()

	// Possible rollback version
	v456Valid := testAgentVersion{
		version: "4.5.6",
		hash:    "valid1",
	}

	// Installed test agent version
	v789Actual := testAgentVersion{
		version: "7.8.9",
		hash:    "actual",
	}

	// min and max duration for cleanup scheduling
	cleanupInterval := 10 * time.Minute

	type args struct {
		currentVersionedHome string
		minInterval          time.Duration
	}

	tests := []struct {
		name       string
		setup      func(t *testing.T, log *logger.Logger, topDir string, source *mockAvailableRollbacksSource)
		args       args
		want       time.Time
		assertions func(t *testing.T, topDir string, source *mockAvailableRollbacksSource)
	}{
		{
			name: "No available rollbacks: keep checking every cleanupInterval",
			setup: func(t *testing.T, log *logger.Logger, topDir string, source *mockAvailableRollbacksSource) {
				source.EXPECT().Get().Return(nil, nil)
				// setup the fake agent installations
				setupAgents(t, log, topDir, setupAgentInstallations{
					installedAgents: []testAgentInstall{
						{
							version:          v789Actual,
							useVersionInPath: true,
						},
					},
					upgradeFrom:  testAgentVersion{},
					upgradeTo:    testAgentVersion{},
					currentAgent: v789Actual,
				},
					false,
				)
			},
			args: args{
				currentVersionedHome: filepath.Join("data", "elastic-agent-7.8.9-actual"),
				minInterval:          cleanupInterval,
			},
			want: now.Add(cleanupInterval),
			assertions: func(t *testing.T, topDir string, source *mockAvailableRollbacksSource) {
				assert.DirExists(t, filepath.Join(topDir, "data", "elastic-agent-7.8.9-actual"))
			},
		},
		{
			name: "Available rollback expiring in the future: check again at expiration time",
			setup: func(t *testing.T, log *logger.Logger, topDir string, source *mockAvailableRollbacksSource) {
				// setup the fake agent installations
				setupAgents(t, log, topDir, setupAgentInstallations{
					installedAgents: []testAgentInstall{
						{
							version:          v456Valid,
							useVersionInPath: true,
						},
						{
							version:          v789Actual,
							useVersionInPath: true,
						},
					},
					upgradeFrom:  testAgentVersion{},
					upgradeTo:    testAgentVersion{},
					currentAgent: v789Actual,
				},
					false,
				)

				// return rollback expiring in the future
				source.EXPECT().Get().Return(
					map[string]ttl.TTLMarker{
						filepath.Join("data", "elastic-agent-4.5.6-valid1"): {
							Version:    "4.5.6",
							Hash:       "valid1",
							ValidUntil: now.Add(1 * time.Hour),
						},
					},
					nil)
			},
			args: args{
				currentVersionedHome: filepath.Join("data", "elastic-agent-7.8.9-actual"),
				minInterval:          cleanupInterval,
			},
			want: now.Add(1 * time.Hour),
			assertions: func(t *testing.T, topDir string, source *mockAvailableRollbacksSource) {
				assert.DirExists(t, filepath.Join(topDir, "data", "elastic-agent-7.8.9-actual"))
				assert.DirExists(t, filepath.Join(topDir, "data", "elastic-agent-4.5.6-valid1"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			topDir := t.TempDir()
			log, _ := loggertest.New(t.Name())
			source := newMockAvailableRollbacksSource(t)
			tt.setup(t, log, topDir, source)
			nextRunTime := performScheduledCleanup(log, topDir, tt.args.currentVersionedHome, source, now, tt.args.minInterval)
			assert.Equal(t, tt.want, nextRunTime)
			if tt.assertions != nil {
				tt.assertions(t, topDir, source)
			}
		})
	}
}

func TestPeriodicallyCleanRollbacks(t *testing.T) {

	// min and max duration for cleanup scheduling
	minInterval := time.Millisecond

	tests := []struct {
		name            string
		setup           func(t *testing.T, log *logger.Logger, topDir string, source *mockAvailableRollbacksSource)
		handleGoroutine func(t *testing.T, cancel context.CancelFunc, appDone chan bool)
	}{
		{
			name: "Goroutine stops when context expires",
			setup: func(t *testing.T, log *logger.Logger, topDir string, source *mockAvailableRollbacksSource) {
				source.EXPECT().Get().Return(nil, nil).Maybe()
			},
			handleGoroutine: func(t *testing.T, cancel context.CancelFunc, appDone chan bool) {
				// give some time to get the goroutine running
				<-time.After(5 * minInterval)
				cancel()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			topDir := t.TempDir()
			log, _ := loggertest.New(t.Name())
			source := newMockAvailableRollbacksSource(t)
			tt.setup(t, log, topDir, source)
			wg := new(sync.WaitGroup)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			appDone := make(chan bool, 1)
			// launch goroutine
			wg.Add(1)
			go func() {
				defer wg.Done()
				PeriodicallyCleanRollbacks(ctx, log, topDir, "notreallyimportant", source, minInterval)
			}()

			tt.handleGoroutine(t, cancel, appDone)
			wg.Wait()
		})
	}
}
