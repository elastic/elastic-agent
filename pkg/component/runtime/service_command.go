// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dolmen-go/contextio"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func executeCommand(ctx context.Context, log *logger.Logger, binaryPath string, args []string, env []string, timeout time.Duration) error {
	log = log.With("context", "command output")
	// Create context with timeout if the timeout is greater than 0
	if timeout > 0 {
		var cn context.CancelFunc
		ctx, cn = context.WithTimeout(ctx, timeout)
		defer cn()
	}

	cmd := exec.CommandContext(ctx, binaryPath, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}

	// Set the command working directory from binary
	// This is needed because the endpoint installer was looking for it's resources in the current working directory
	wdir := filepath.Dir(binaryPath)
	if wdir != "." {
		cmd.Dir = wdir
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed getting stderr for the command: %w", err)
	}

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("failed starting the command: %w", err)
	}

	// channel for the last error message from the stderr output
	errch := make(chan string, 1)
	ctxstderr := contextio.NewReader(ctx, stderr)
	go func() {
		var errtext string
		scanner := bufio.NewScanner(ctxstderr)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) > 0 {
				txt := strings.TrimSpace(string(line))
				if len(txt) > 0 {
					errtext = strings.TrimSpace(string(line))
					// Log error output line
					log.Error(errtext)
				}
			}
		}
		errch <- errtext
	}()

	err = cmd.Wait()
	if err != nil {
		var exerr *exec.ExitError
		// If the process was killed, check if timeout
		if errors.As(err, &exerr) && exerr.ExitCode() == -1 && ctx.Err() != nil {
			err = ctx.Err()
		}

		select {
		case errmsg := <-errch:
			errmsg = strings.TrimSpace(errmsg)
			if errmsg != "" {
				err = fmt.Errorf("%s: %w", errmsg, err)
			}
		default:
		}
	}

	return err
}

func executeServiceCommand(ctx context.Context, log *logger.Logger, binaryPath string, spec *component.ServiceOperationsCommandSpec) error {
	if spec == nil {
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
