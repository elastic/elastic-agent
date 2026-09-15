// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"context"
	"net"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

// opampPipeAddress is the npipe address for the OpAMP server's named pipe.
// ipc.CreateListener converts this to \\.\pipe\elastic-agent-opamp via
// npipe.TransformString, which requires the npipe:/// (three-slash) prefix.
const opampPipeAddress = "npipe:///elastic-agent-opamp"

// listenOpAMPSocket creates the platform IPC listener for the OpAMP server.
// On Windows this is a named pipe; ipc.CreateListener sets the correct security
// descriptor (owner + SYSTEM + Administrators, plus group SID when unprivileged).
func listenOpAMPSocket(_ context.Context, log *logger.Logger) (net.Listener, error) {
	return ipc.CreateListener(log, opampPipeAddress)
}
