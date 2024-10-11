// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package server

import (
	"net"

	"github.com/elastic/elastic-agent/pkg/control"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

func createListener(log *logger.Logger) (net.Listener, error) {
	return ipc.CreateListener(log, control.Address())
}

func cleanupListener(log *logger.Logger) {
	ipc.CleanupListener(log, control.Address())
}
