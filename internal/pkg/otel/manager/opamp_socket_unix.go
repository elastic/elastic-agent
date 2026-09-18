// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package manager

import (
	"net"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

// listenOpAMPSocket creates the platform IPC listener for the OpAMP server.
// On Unix this is a Unix domain socket; ipc.CreateListener handles stale-file
// removal and permission hardening (0700 / 0770).
func listenOpAMPSocket(log *logger.Logger) (net.Listener, error) {
	addr := "unix://" + filepath.Join(paths.Top(), "opamp.sock")
	return ipc.CreateListener(log, addr)
}
