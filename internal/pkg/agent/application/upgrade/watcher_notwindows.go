// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package upgrade

import (
	"context"
	"os"
	"os/exec"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

func createTakeDownWatcherCommand(ctx context.Context) *exec.Cmd {
	executable, _ := os.Executable()

	// #nosec G204 -- user cannot inject any parameters to this command
	cmd := exec.CommandContext(ctx, executable, watcherSubcommand,
		"--path.config", paths.Config(),
		"--path.home", paths.Top(),
		"--takedown",
	)
	return cmd
}
