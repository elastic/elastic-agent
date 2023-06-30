// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"text/template"
	"time"

	"go.uber.org/zap/zaptest/observer"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/zap/zapcore"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type progConfig struct {
	ErrMessage   string
	ExitCode     int
	SleepMS      int
	SucceedAfter int64 // ms since unix epoch
}

const testProgramTemplate = `
package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	if {{.SucceedAfter}} > 0 {
		if time.Now().After(time.UnixMilli({{.SucceedAfter}})) {
			fmt.Fprintln(os.Stderr, "testprog succeeded")
			os.Exit(0)
		}
	}

	if len("{{.ErrMessage}}") > 0 {
		fmt.Fprintf(os.Stderr, "{{.ErrMessage}}")
	}
	if {{.SleepMS}} != 0 {
		time.Sleep(time.Duration({{.SleepMS}})*time.Millisecond)
	}
	if {{.ExitCode}} != 0 {
		os.Exit({{.ExitCode}})
	}
}
`
const testModFile = `
module prog

go 1.19
`

func renderTestProg(cfg progConfig) string {
	t := template.Must(template.New("prog").Parse(testProgramTemplate))
	var b strings.Builder
	err := t.Execute(&b, cfg)
	if err != nil {
		panic(err)
	}
	return b.String()
}

func getExeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func prepareTestProg(ctx context.Context, log *logger.Logger, dir string, cfg progConfig) (string, error) {
	const name = "prog"

	progPath := filepath.Join(dir, name+".go")

	prog := renderTestProg(cfg)
	err := os.WriteFile(progPath, []byte(prog), 0600)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(filepath.Join(dir, "go.mod"), []byte(testModFile), 0600)
	if err != nil {
		return "", err
	}

	err = executeCommand(ctx, log, "go", []string{"build", "-o", dir, progPath}, nil, 0)
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, getExeName(name)), nil
}

func TestExecuteCommand(t *testing.T) {
	log := logp.NewLogger("test_service")

	tests := []struct {
		name    string
		cfg     progConfig
		timeout time.Duration
		wantErr error
	}{
		{
			name: "success",
		},
		{
			name: "fail no error output",
			cfg:  progConfig{"", 1, 0, 0},
		},
		{
			name: "fail with error output",
			cfg:  progConfig{"something failed", 2, 0, 0},
		},
		{
			name:    "fail with timeout",
			cfg:     progConfig{"", 3, 5000, 0}, // executable runs for 5 seconds
			timeout: 100 * time.Millisecond,
			wantErr: context.DeadlineExceeded,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cn := context.WithCancel(context.Background())
			defer cn()

			dir := t.TempDir()

			// Prepare test program with expected param
			exePath, err := prepareTestProg(ctx, log, dir, tc.cfg)
			if err != nil {
				t.Fatal(err)
			}

			err = executeCommand(ctx, log, exePath, nil, nil, tc.timeout)

			if tc.wantErr != nil {
				diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors())
				if diff != "" {
					t.Fatal(diff)
				}
			} else {
				// If exit code is not 0, expect error
				if tc.cfg.ExitCode == 0 {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					if err != nil {
						var exerr *exec.ExitError
						if errors.As(err, &exerr) {
							diff := cmp.Diff(tc.cfg.ExitCode, exerr.ExitCode())
							if diff != "" {
								t.Fatal(diff)
							}
						} else {
							t.Fatalf("want *exec.ExitError, got %T", err)
						}
					} else {
						t.Fatalf("want error code %v, got nil", tc.cfg.ExitCode)
					}
				}
			}

			// Test that we get the proper error message
			// The stderr message is prepended to the err, separated with ':', for example "something failed: exit status 2"
			if err != nil && tc.cfg.ErrMessage != "" {
				arr := strings.Split(err.Error(), ":")
				diff := cmp.Diff(tc.cfg.ErrMessage, arr[0])
				if diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}

}

func TestExecuteServiceCommand(t *testing.T) {
	// No spec
	t.Run("no_spec", func(t *testing.T) {
		ctx := context.Background()
		log, obs := logger.NewTesting(t.Name())

		exePath, err := prepareTestProg(ctx, log, t.TempDir(), progConfig{})
		require.NoError(t, err)

		err = executeServiceCommand(ctx, log, exePath, nil, false)
		require.NoError(t, err)

		warnLogs := obs.FilterLevelExact(zapcore.WarnLevel)
		require.Equal(t, 1, warnLogs.Len())
		require.Equal(t, fmt.Sprintf("spec is nil, nothing to execute, binaryPath: %s", exePath), warnLogs.TakeAll()[0].Message)
	})

	// Execution fails (without retries)
	t.Run("no_retries_failed_execution", func(t *testing.T) {
		ctx := context.Background()
		log, obs := logger.NewTesting(t.Name())

		exeConfig := progConfig{
			ErrMessage: "foo bar",
			ExitCode:   111,
		}
		exePath, err := prepareTestProg(ctx, log, t.TempDir(), exeConfig)
		require.NoError(t, err)

		err = executeServiceCommand(ctx, log, exePath, &component.ServiceOperationsCommandSpec{}, false)
		require.EqualError(t, err, fmt.Sprintf("%s: exit status %d", exeConfig.ErrMessage, exeConfig.ExitCode))

		require.Equal(t, 1, obs.Len())
		logs := obs.TakeAll()
		require.Equal(t, zapcore.ErrorLevel, logs[0].Level)
		require.Equal(t, exeConfig.ErrMessage, logs[0].Message)
	})

	// Execution succeeds (without retries)
	t.Run("no_retries_successful_execution", func(t *testing.T) {
		ctx := context.Background()
		log, obs := logger.NewTesting(t.Name())

		exePath, err := prepareTestProg(ctx, log, t.TempDir(), progConfig{})
		require.NoError(t, err)

		err = executeServiceCommand(ctx, log, exePath, &component.ServiceOperationsCommandSpec{}, false)
		require.NoError(t, err)

		require.Equal(t, 0, obs.Len())
	})

	// Execution succeeds on first attempt (with retries)
	t.Run("with_retries_successful_execution", func(t *testing.T) {
		ctx := context.Background()
		log, obs := logger.NewTesting(t.Name())

		exePath, err := prepareTestProg(ctx, log, t.TempDir(), progConfig{})
		require.NoError(t, err)

		err = executeServiceCommand(ctx, log, exePath, &component.ServiceOperationsCommandSpec{}, true)
		require.NoError(t, err)

		// Remove debug-level logs as those are only being emitted from
		// retrier internals.
		obs = obs.Filter(func(entry observer.LoggedEntry) bool {
			return entry.Level != zapcore.DebugLevel
		})

		require.Equal(t, 0, obs.Len())
	})

	// Execution fails indefinitely and there is no retry configuration in spec
	t.Run("failed_execution_no_retry_config", func(t *testing.T) {
		cmdCtx := context.Background()
		log, obs := logger.NewTesting(t.Name())

		exeConfig := progConfig{
			ErrMessage: "foo bar",
			ExitCode:   111,
		}
		exePath, err := prepareTestProg(cmdCtx, log, t.TempDir(), exeConfig)
		require.NoError(t, err)

		// Since the service command is retried indefinitely, we need a way to
		// stop the test within a reasonable amount of time
		retryCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		defaultRetryInitInterval := 50 * time.Millisecond
		retryMaxInterval := 200 * time.Millisecond

		executeServiceCommandWithRetries(
			cmdCtx, log, exePath, &component.ServiceOperationsCommandSpec{},
			retryCtx, defaultRetryInitInterval, retryMaxInterval,
		)

		<-retryCtx.Done()
		checkRetryLogs(t, obs, exeConfig)
	})

	// Execution fails indefinitely but there is retry configuration in spec
	t.Run("failed_execution_with_retry_config", func(t *testing.T) {
		cmdCtx := context.Background()
		log, obs := logger.NewTesting(t.Name())

		exeConfig := progConfig{
			ErrMessage: "foo bar",
			ExitCode:   111,
		}
		exePath, err := prepareTestProg(cmdCtx, log, t.TempDir(), exeConfig)
		require.NoError(t, err)

		// Since the service command is retried indefinitely, we need a way to
		// stop the test within a reasonable amount of time
		retryCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		defaultRetryInitInterval := 50 * time.Millisecond
		retryMaxInterval := 1 * time.Second

		spec := &component.ServiceOperationsCommandSpec{
			// We deliberately set RetrySleepInitDuration to just shorter
			// than the retryCtx timeout. With this we should observe:
			// - the initial execution of the command (before any retries)
			// - one message about the next (first) retry
			// - one more execution of the command, as a result of the first retry
			// - one message about the next (second) retry
			Retry: component.RetryConfig{
				InitInterval: 700 * time.Millisecond,
			},
		}
		executeServiceCommandWithRetries(
			cmdCtx, log, exePath, spec,
			retryCtx, defaultRetryInitInterval, retryMaxInterval,
		)

		<-retryCtx.Done()
		checkRetryLogs(t, obs, exeConfig)
	})

	// Execution fails initially but then succeeds after a few retries
	t.Run("succeed_after_retry", func(t *testing.T) {
		cmdCtx := context.Background()
		log, obs := logger.NewTesting(t.Name())

		const succeedCmdAfter = 3 * time.Second
		now := time.Now()
		exeConfig := progConfig{
			ErrMessage:   "foo bar",
			ExitCode:     111,
			SucceedAfter: now.Add(succeedCmdAfter).UnixMilli(),
		}
		exePath, err := prepareTestProg(cmdCtx, log, t.TempDir(), exeConfig)
		require.NoError(t, err)

		// Since the service command is retried indefinitely, we need a way to
		// stop the test within a reasonable amount of time. However, we should never
		// hit this timeout as the command should succeed before the timeout is reached.
		retryCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()

		defaultRetryInitInterval := 50 * time.Millisecond
		retryMaxInterval := 1 * time.Second

		spec := &component.ServiceOperationsCommandSpec{
			Retry: component.RetryConfig{
				InitInterval: 200 * time.Millisecond,
			},
		}
		executeServiceCommandWithRetries(
			cmdCtx, log, exePath, spec,
			retryCtx, defaultRetryInitInterval, retryMaxInterval,
		)

		// Give the command time to succeed.
		successMsgFilterFn := func(l observer.LoggedEntry) bool {
			return strings.Contains(l.Message, "testprog succeeded")
		}
		require.Eventually(t, func() bool {
			return obs.Filter(successMsgFilterFn).Len() == 1
		}, 5*time.Second, 1*time.Second)

		require.NoError(t, retryCtx.Err())

		obs = obs.Filter(func(l observer.LoggedEntry) bool {
			return !successMsgFilterFn(l)
		})
		checkRetryLogs(t, obs, exeConfig)
	})

	// Ensure two calls to executeServiceCommandWithRetries cancels
	// the previous command execution.
	t.Run("previous_execution_cancels", func(t *testing.T) {
		log, obs := logger.NewTesting(t.Name())

		exeConfig := progConfig{
			ErrMessage: "foo bar",
			ExitCode:   111,
		}
		exePath, err := prepareTestProg(context.Background(), log, t.TempDir(), exeConfig)
		require.NoError(t, err)

		defaultRetryInitInterval := 50 * time.Millisecond
		retryMaxInterval := 200 * time.Millisecond

		// First call
		cmd1Ctx := context.Background()
		retry1Ctx := context.Background()

		executeServiceCommandWithRetries(
			cmd1Ctx, log, exePath, &component.ServiceOperationsCommandSpec{},
			retry1Ctx, defaultRetryInitInterval, retryMaxInterval,
		)

		debugLogs := obs.FilterLevelExact(zapcore.DebugLevel).TakeAll()
		require.Len(t, debugLogs, 1)
		require.Equal(t,
			fmt.Sprintf(
				"no retries for command key [%s] are pending; nothing to do",
				serviceCmdRetrier.cmdKey(exePath, nil, nil),
			),
			debugLogs[0].Message,
		)

		// Second call
		cmd2Ctx := context.Background()
		// Since the service command is retried indefinitely, we need a way to
		// stop the test within a reasonable amount of time. However, we should never
		// hit this timeout as the command should succeed before the timeout is reached.
		retry2Ctx, cancel2 := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel2()

		executeServiceCommandWithRetries(
			cmd2Ctx, log, exePath, &component.ServiceOperationsCommandSpec{},
			retry2Ctx, defaultRetryInitInterval, retryMaxInterval,
		)

		debugLogs = obs.FilterLevelExact(zapcore.DebugLevel).TakeAll()
		require.Len(t, debugLogs, 2)
		require.Equal(t,
			fmt.Sprintf(
				"retries and command process for command key [%s] stopped",
				serviceCmdRetrier.cmdKey(exePath, nil, nil),
			),
			debugLogs[1].Message,
		)

		<-retry2Ctx.Done()

		checkRetryLogs(t, obs, exeConfig)
	})
}

func checkRetryLogs(t *testing.T, obs *observer.ObservedLogs, exeConfig progConfig) {
	t.Helper()

	// Remove debug-level logs as those are only being emitted from
	// retrier internals.
	obs = obs.Filter(func(entry observer.LoggedEntry) bool {
		return entry.Level != zapcore.DebugLevel
	})

	// We expect there to be at least 2 log entries as this would indicate that
	// at least one round of retries was attempted.
	logs := obs.TakeAll()
	require.GreaterOrEqual(t, len(logs), 2)

	for i, l := range logs {
		if i%2 == 0 {
			require.Equal(t, zapcore.ErrorLevel, l.Level)
			require.Equal(t, exeConfig.ErrMessage, l.Message)
		} else {
			require.Equal(t, zapcore.WarnLevel, l.Level)
			require.Contains(t, l.Message, fmt.Sprintf(
				"service command execution failed with error [%s: exit status %d], retrying (will be retry [%d]) after",
				exeConfig.ErrMessage, exeConfig.ExitCode, (i/2)+1,
			))
		}
	}
}
