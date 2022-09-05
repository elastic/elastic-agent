// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dolmen-go/contextio"
	"github.com/elastic/elastic-agent/pkg/component"
)

const maxErrOutputLen = 1024

func executeCommand(ctx context.Context, binaryPath string, args []string, env []string, timeout time.Duration) error {
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

	var errbuf strings.Builder
	ctxstderr := contextio.NewReader(ctx, stderr)
	if _, err := io.CopyN(&errbuf, ctxstderr, maxErrOutputLen); err != nil {
		if !errors.Is(err, io.EOF) {
			return err
		}
	}

	err = cmd.Wait()

	if err != nil {
		var exerr *exec.ExitError
		// If the process was killed, check if timeout
		if errors.As(err, &exerr) && exerr.ExitCode() == -1 && ctx.Err() != nil {
			err = ctx.Err()
		}

		errmsg := strings.TrimSpace(errbuf.String())
		if errmsg != "" {
			err = fmt.Errorf("%s: %w", errmsg, err)
		}
	}
	return err
}

func executeServiceCommand(ctx context.Context, binaryPath string, spec *component.ServiceOperationsCommandSpec) error {
	if spec == nil {
		return nil
	}
	return executeCommand(ctx, binaryPath, spec.Args, envSpecToEnv(spec.Env), spec.Timeout)
}

func envSpecToEnv(envSpecs []component.CommandEnvSpec) []string {
	if envSpecs == nil {
		return nil
	}

	env := make([]string, len(envSpecs))

	for i, spec := range envSpecs {
		env[i] = spec.Name + "=" + spec.Value
	}
	return env
}
