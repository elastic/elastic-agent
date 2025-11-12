// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
