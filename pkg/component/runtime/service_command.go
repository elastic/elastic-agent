// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dolmen-go/contextio"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/process"
)

// Lines of command output have the form "<date> <time>: <level>: <message>".
var (
	errorLevelLine = regexp.MustCompile(`^\S+ \S+: error: `)
	logLinePrefix  = regexp.MustCompile(`^\S+ \S+: \w+: `)
)

// commandError is the error of a failed command. Its text is the last line of the
// command output followed by the reason the command failed. It also keeps the last
// line logged at the error level, if there was one.
type commandError struct {
	line      string
	errorLine string
	err       error
}

func (e *commandError) Error() string { return e.line + ": " + e.err.Error() }

// summary returns the line of the command output that best describes the failure.
func (e *commandError) summary() string {
	if e.errorLine != "" {
		return e.errorLine
	}
	return e.line
}

func (e *commandError) Unwrap() error { return e.err }

// outputLines are the lines of the command output used to describe a failure.
type outputLines struct {
	last      string
	lastError string
}

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

	// channel for the last line and the last error level line of the stderr output
	errch := make(chan outputLines, 1)
	ctxStderr := contextio.NewReader(ctx, proc.Stderr)
	go func() {
		var lastLine, lastErrorLine string
		scanner := bufio.NewScanner(ctxStderr)
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) > 0 {
				txt := strings.TrimSpace(line)
				if len(txt) > 0 {
					lastLine = txt
					if errorLevelLine.MatchString(txt) {
						lastErrorLine = txt
					}
					// Log error output line
					log.Error(txt)
				}
			}
		}
		errch <- outputLines{last: lastLine, lastError: lastErrorLine}
	}()

	procState := <-proc.Wait()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = ctx.Err() // Process was killed due to timeout
	} else if !procState.Success() {
		err = &exec.ExitError{ProcessState: procState}
	}

	if err != nil {
		lines := <-errch
		errmsg := strings.TrimSpace(lines.last)
		if errmsg != "" {
			err = &commandError{line: errmsg, errorLine: lines.lastError, err: err}
		}
	}

	return err
}

func executeServiceCommand(ctx context.Context, log *logger.Logger, binaryPath string, spec *component.ServiceOperationsCommandSpec) error {
	if spec == nil {
		log.Warnf("spec is nil, nothing to execute, binaryPath: %s", binaryPath)
		return nil
	}
	return executeCommand(ctx, log, binaryPath, spec.Args, envSpecToEnv(spec.Env), spec.Timeout)
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
