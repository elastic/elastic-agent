// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

const applockerFileName = "mocklocker.lock"

func Test_watchLoop(t *testing.T) {

	t.Run("watchloop returns when context expires - no error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		log, _ := loggertest.New(t.Name())
		signals := make(chan os.Signal, 1)
		errChan := make(chan error, 1)
		graceTimer := make(chan time.Time, 1)
		err := watchLoop(ctx, log, signals, errChan, graceTimer)
		require.NoError(t, err)
	})

	t.Run("watchloop returns when grace timer triggers - no error", func(t *testing.T) {
		log, _ := loggertest.New(t.Name())
		signals := make(chan os.Signal, 1)
		errChan := make(chan error, 1)
		graceTimer := make(chan time.Time, 1)
		graceTimer <- time.Now()
		err := watchLoop(t.Context(), log, signals, errChan, graceTimer)
		require.NoError(t, err)
	})

	t.Run("watchloop returns when error from AgentWatcher is received - error", func(t *testing.T) {
		log, _ := loggertest.New(t.Name())
		signals := make(chan os.Signal, 1)
		errChan := make(chan error, 1)
		graceTimer := make(chan time.Time, 1)
		agentWatcherError := fmt.Errorf("some error")
		errChan <- agentWatcherError
		err := watchLoop(t.Context(), log, signals, errChan, graceTimer)
		require.ErrorIs(t, err, agentWatcherError)
	})

	t.Run("watchloop returns when receiving signals - error", func(t *testing.T) {
		testSignals := []syscall.Signal{
			syscall.SIGTERM,
			syscall.SIGINT,
		}

		for _, signal := range testSignals {
			t.Run(signal.String(), func(t *testing.T) {
				log, _ := loggertest.New(t.Name())
				signals := make(chan os.Signal, 1)
				errChan := make(chan error, 1)
				graceTimer := make(chan time.Time, 1)
				signals <- signal
				err := watchLoop(t.Context(), log, signals, errChan, graceTimer)
				assert.ErrorIs(t, err, ErrWatchCancelled)
			})
		}
	})
}

func Test_takedownWatcher(t *testing.T) {

	testExecutablePath := filepath.Join("..", "application", "filelock", "testlocker", "testlocker")
	if runtime.GOOS == "windows" {
		testExecutablePath += ".exe"
	}
	testExecutableAbsolutePath, err := filepath.Abs(testExecutablePath)
	require.NoError(t, err, "error calculating absolute test executable part")

	require.FileExists(t, testExecutableAbsolutePath,
		"testlocker binary not found.\n"+
			"Check that:\n"+
			"- test binaries have been built with mage build:testbinaries\n"+
			"- the path of the executable is correct")

	returnCmdPIDsFetcher := func(cmds ...*exec.Cmd) watcherPIDsFetcher {
		return func() ([]int, error) {
			pids := make([]int, 0, len(cmds))
			for _, c := range cmds {
				if c.Process != nil {
					pids = append(pids, c.Process.Pid)
				}
			}

			return pids, nil
		}
	}

	type setupFunc func(t *testing.T, workdir string) (watcherPIDsFetcher, []*exec.Cmd)
	type assertFunc func(t *testing.T, workdir string, cmds []*exec.Cmd)

	tests := []struct {
		name               string
		setup              setupFunc
		wantErr            assert.ErrorAssertionFunc
		assertPostTakedown assertFunc
	}{
		{
			name: "no contention for watcher applocker",
			setup: func(t *testing.T, workdir string) (watcherPIDsFetcher, []*exec.Cmd) {
				// nothing to do here, always return and empty list of pids
				return func() ([]int, error) {
					return nil, nil
				}, nil
			},
			wantErr: assert.NoError,
			assertPostTakedown: func(t *testing.T, workdir string, _ []*exec.Cmd) {
				// we should be able to lock, no problem
				locker := filelock.NewAppLocker(workdir, applockerFileName)
				lockError := locker.TryLock()
				t.Cleanup(func() {
					_ = locker.Unlock()
				})

				assert.NoError(t, lockError)

			},
		},
		{
			name: "contention with test binary listening to signals: test binary is terminated gracefully",
			setup: func(t *testing.T, workdir string) (watcherPIDsFetcher, []*exec.Cmd) {
				cmd := createTestlockerCommand(t, testExecutableAbsolutePath, workdir, false)
				require.NoError(t, err, "error starting testlocker binary")

				// wait for test binary to acquire lock
				require.EventuallyWithT(t, func(collect *assert.CollectT) {
					assert.FileExists(collect, filepath.Join(workdir, applockerFileName), "watcher applocker should have been created by the test binary")
				}, 10*time.Second, 100*time.Millisecond)
				require.NotNil(t, cmd.Process, "process details for testlocker should not be nil")

				t.Logf("started testlocker process with PID %d", cmd.Process.Pid)

				return returnCmdPIDsFetcher(cmd), []*exec.Cmd{cmd}
			},
			wantErr: assert.NoError,
			assertPostTakedown: func(t *testing.T, workdir string, cmds []*exec.Cmd) {

				assert.Len(t, cmds, 1)
				testlockerProcess := cmds[0]
				require.NotNil(t, testlockerProcess, "test locker process info should have a not nil cmd")

				err = testlockerProcess.Wait()
				assert.NoError(t, err, "error waiting for testlocker process to terminate")

				if assert.NotNil(t, testlockerProcess.ProcessState, "test locker process should have completed and process state set") {
					assert.True(t, testlockerProcess.ProcessState.Success(), "test locker process should be successful")
				}

				assert.FileExists(t, filepath.Join(workdir, applockerFileName))
				testApplocker := filelock.NewAppLocker(workdir, applockerFileName)
				testApplockerError := testApplocker.TryLock()
				t.Cleanup(func() {
					_ = testApplocker.Unlock()
				})
				assert.NoError(t, testApplockerError, "error locking applocker")
			},
		},
		{
			name: "contention with test binary not listening to signals: test binary is not terminated",
			setup: func(t *testing.T, workdir string) (watcherPIDsFetcher, []*exec.Cmd) {
				cmd := createTestlockerCommand(t, testExecutableAbsolutePath, workdir, true)
				require.NoError(t, err, "error starting testlocker binary")

				// wait for test binary to acquire lock
				require.EventuallyWithT(t, func(collect *assert.CollectT) {
					assert.FileExists(collect, filepath.Join(workdir, applockerFileName), "watcher applocker should have been created by the test binary")
				}, 10*time.Second, 100*time.Millisecond)
				require.NotNil(t, cmd.Process, "process details for testlocker should not be nil")

				t.Logf("started testlocker process with PID %d", cmd.Process.Pid)

				return returnCmdPIDsFetcher(cmd), []*exec.Cmd{cmd}
			},
			wantErr: assert.NoError,
			assertPostTakedown: func(t *testing.T, workdir string, cmds []*exec.Cmd) {

				assert.Len(t, cmds, 1)
				testlockerProcess := cmds[0]
				require.NotNil(t, testlockerProcess, "test locker process info should have exec.Cmd set")

				// check that the process is still running
				assert.Nil(t, testlockerProcess.ProcessState, "testlocker process should not have ProcessState set since it should still be running")
				assert.NotNil(t, testlockerProcess.Process, "testlocker process should have an os.Process set")
				process, findProcessErr := os.FindProcess(testlockerProcess.Process.Pid)
				require.NoErrorf(t, findProcessErr, "error finding test process with pid %d", testlockerProcess.Process.Pid)
				require.NotNil(t, process, "test process should be found among the running processes")
				if runtime.GOOS != "windows" {
					// for unix systems we need an additional check since FindProcess will always return a *os.Process.
					// Poke it with a stick (signal)
					// see https://pkg.go.dev/os#FindProcess
					signalErr := process.Signal(syscall.Signal(0))
					require.NoError(t, signalErr, "error signaling test process: this means it's not running")
				}
				err := testlockerProcess.Process.Kill()
				assert.NoError(t, err, "error killing testlocker process")
				assert.Nil(t, testlockerProcess.ProcessState, "testlocker process should not have ProcessState set since it should still be running")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			workDir := t.TempDir()
			log, obsLogs := loggertest.New(t.Name())
			pidFetcher, processInfos := tc.setup(t, workDir)
			tc.wantErr(t, takedownWatcher(log, pidFetcher))
			t.Logf("takedown logs: %v", obsLogs)
			if tc.assertPostTakedown != nil {
				tc.assertPostTakedown(t, workDir, processInfos)
			}
		})
	}
}

func createTestlockerCommand(t *testing.T, testExecutablePath string, workdir string, ignoreSignals bool) *exec.Cmd {
	args := []string{"-lockfile", filepath.Join(workdir, applockerFileName)}
	if ignoreSignals {
		args = append(args, "-ignoresignals")
	}

	// use the same invoke as the one used to launch a watcher
	cmd := upgrade.InvokeCmdWithArgs(testExecutablePath, args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	require.NoError(t, err, "error starting testlocker binary")
	return cmd
}
