// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/dolmen-go/contextio"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

var serviceCmdRetrier = cmdRetrier{}

func executeCommand(ctx context.Context, log *logger.Logger, binaryPath string, args []string, env []string, timeout time.Duration) error {
	log = log.With("context", "command output")
	// Create context with timeout if the timeout is greater than 0
	if timeout > 0 {
		var cn context.CancelFunc
		ctx, cn = context.WithTimeout(ctx, timeout)
		defer cn()
	}

	opts := []process.StartOption{
		process.WithContext(ctx),
		process.WithArgs(args),
		process.WithEnv(env),
	}

	// Set the command working directory from binary
	// This is needed because the endpoint installer was looking for it's resources in the current working directory
	wdir := filepath.Dir(binaryPath)
	if wdir != "." {
		opts = append(opts,
			process.WithCmdOptions(func(c *exec.Cmd) error {
				c.Dir = wdir
				return nil
			}))
	}

	proc, err := process.Start(binaryPath, opts...)
	if err != nil {
		return fmt.Errorf("failed starting the command: %w", err)
	}

	// channel for the last error message from the stderr output
	errch := make(chan string, 1)
	ctxStderr := contextio.NewReader(ctx, proc.Stderr)
	go func() {
		var errText string
		scanner := bufio.NewScanner(ctxStderr)
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) > 0 {
				txt := strings.TrimSpace(line)
				if len(txt) > 0 {
					errText = txt
					// Log error output line
					log.Error(errText)
				}
			}
		}
		errch <- errText
	}()

	procState := <-proc.Wait()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = ctx.Err() // Process was killed due to timeout
	} else if !procState.Success() {
		err = &exec.ExitError{ProcessState: procState}
	}

	if err != nil {
		errmsg := <-errch
		errmsg = strings.TrimSpace(errmsg)
		if errmsg != "" {
			err = fmt.Errorf("%s: %w", errmsg, err)
		}
	}

	return err
}

func executeServiceCommand(ctx context.Context, log *logger.Logger, binaryPath string, spec *component.ServiceOperationsCommandSpec) error {
	return executeServiceCommandWithRetries(
		ctx, log, binaryPath, spec,
		context.Background(), 20*time.Second, 15*time.Minute,
	)
}

func executeServiceCommandWithRetries(
	cmdCtx context.Context, log *logger.Logger, binaryPath string, spec *component.ServiceOperationsCommandSpec,
	retryCtx context.Context, defaultRetrySleepInitDuration time.Duration, retrySleepMaxDuration time.Duration,
) error {
	if spec == nil {
		log.Warnf("spec is nil, nothing to execute, binaryPath: %s", binaryPath)
		return nil
	}

	// If no initial sleep duration is specified, use default value
	retrySleepInitDuration := spec.RetrySleepInitDuration
	if retrySleepInitDuration == 0 {
		retrySleepInitDuration = defaultRetrySleepInitDuration
	}

	serviceCmdRetrier.Start(
		cmdCtx, log,
		binaryPath, spec.Args, envSpecToEnv(spec.Env), spec.Timeout,
		retryCtx, retrySleepInitDuration, retrySleepMaxDuration,
	)
	return nil
}

type cmdRetryInfo struct {
	retryCancelFn context.CancelFunc
	cmdCancelFn   context.CancelFunc
	cmdDone       <-chan struct{}
}

type cmdRetrier struct {
	mu   sync.RWMutex
	cmds map[uint64]cmdRetryInfo
}

func (cr *cmdRetrier) Start(
	cmdCtx context.Context, log *logger.Logger,
	binaryPath string, args []string, env []string, timeout time.Duration,
	retryCtx context.Context, retrySleepInitDuration time.Duration, retrySleepMaxDuration time.Duration,
) {
	cmdKey := cr.cmdKey(binaryPath, args, env)

	// Due to infinite retries, we may still be trying to (re)execute
	// a command from a previous call to Start(). We should first stop
	// these retries as well as the command process.
	cr.Stop(cmdKey, log)

	// Track the command so we can cancel it and it's retries later.
	cmdCtx, cmdCancelFn := context.WithCancel(cmdCtx)
	retryCtx, retryCancelFn := context.WithCancel(retryCtx)
	cmdDone := make(chan struct{}, 1)
	cr.track(cmdKey, cmdCancelFn, retryCancelFn, cmdDone)

	// Execute command with retries and exponential backoff between attempts
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = retrySleepInitDuration
	expBackoff.MaxInterval = retrySleepMaxDuration

	backoffCtx := backoff.WithContext(expBackoff, retryCtx)

	// Since we will be executing the command with infinite retries, we don't
	// want to block.  So we execute the command with retries in its own
	// goroutine.
	go func() {
		retryAttempt := 0

		// Here we indefinitely retry the executeCommand call, as long as it
		// returns a non-nil error. We will block here until executeCommand
		// returns a nil error, indicating that the command being executed has
		// successfully completed execution.
		//nolint: errcheck // No point checking the error inside the goroutine.
		backoff.RetryNotify(
			func() error {
				err := executeCommand(cmdCtx, log, binaryPath, args, env, timeout)
				cmdDone <- struct{}{}
				return err
			},
			backoffCtx,
			func(err error, retryAfter time.Duration) {
				retryAttempt++
				log.Warnf(
					"service command execution failed with error [%s], retrying (will be retry [%d]) after [%s]",
					err.Error(),
					retryAttempt,
					retryAfter,
				)
				<-cmdDone
			},
		)

		cr.untrack(cmdKey)
	}()
}

func (cr *cmdRetrier) Stop(cmdKey uint64, log *logger.Logger) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	info, exists := cr.cmds[cmdKey]
	if !exists {
		log.Debugf("no retries for command key [%d] are pending; nothing to do", cmdKey)
		return
	}

	// Cancel the previous retries
	info.retryCancelFn()

	// Cancel the previous command
	info.cmdCancelFn()

	// Ensure that the previous command actually stopped running
	<-info.cmdDone

	// Stop tracking
	delete(cr.cmds, cmdKey)
	log.Debugf("retries and command process for command key [%d] stopped", cmdKey)
}

func (cr *cmdRetrier) track(cmdKey uint64, cmdCancelFn context.CancelFunc, retryCanceFn context.CancelFunc, cmdDone <-chan struct{}) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	// Initialize map if needed
	if cr.cmds == nil {
		cr.cmds = map[uint64]cmdRetryInfo{}
	}

	cr.cmds[cmdKey] = cmdRetryInfo{
		retryCancelFn: retryCanceFn,
		cmdCancelFn:   cmdCancelFn,
		cmdDone:       cmdDone,
	}
}

func (cr *cmdRetrier) untrack(cmdKey uint64) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	delete(cr.cmds, cmdKey)
}

// cmdKey returns a unique, deterministic integer for the combination of the given
// binaryPath, args, and env. This integer can be used to determine if the same command
// is being executed again or not.
func (cr *cmdRetrier) cmdKey(binaryPath string, args []string, env []string) uint64 {
	var sb strings.Builder

	sb.WriteString(binaryPath)
	sb.WriteString("|")

	var posArgs, flagArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg+" "+args[i+1])
			i++
		} else {
			posArgs = append(posArgs, arg)
		}
	}

	sort.Strings(posArgs)
	sort.Strings(flagArgs)

	for _, arg := range posArgs {
		sb.WriteString(arg)
		sb.WriteString("|")
	}

	for _, arg := range flagArgs {
		sb.WriteString(arg)
		sb.WriteString("|")
	}

	sort.Strings(env)

	for _, kv := range env {
		sb.WriteString(kv)
		sb.WriteString("|")
	}

	digest := fnv.New64()
	digest.Write([]byte(sb.String()))

	return digest.Sum64()
}

func envSpecToEnv(envSpecs []component.CommandEnvSpec) []string {
	if len(envSpecs) == 0 {
		return nil
	}

	env := make([]string, len(envSpecs))

	for i, spec := range envSpecs {
		env[i] = spec.Name + "=" + spec.Value
	}
	return env
}
