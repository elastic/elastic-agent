// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package manager

import (
	"net"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

// listenOpAMPSocket creates the platform IPC listener for the OpAMP server.
// On Windows this is a named pipe whose address is derived from paths.OpAMPSocket()
// (a hash-based unique name under \\.\pipe\). ipc.CreateListener sets the correct
// security descriptor (owner + SYSTEM + Administrators, plus group SID when unprivileged).
func listenOpAMPSocket(log *logger.Logger) (net.Listener, error) {
	return ipc.CreateListener(log, paths.OpAMPSocket())
}
