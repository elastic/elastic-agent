// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const schemeUnixPrefix = "unix://"

func IsLocal(address string) bool {
	return strings.HasPrefix(address, schemeUnixPrefix)
}

// CreateListener creates net listener from address string
// Shared for control and beats comms sockets
func CreateListener(log *logger.Logger, address string) (net.Listener, error) {
	path := strings.TrimPrefix(address, schemeUnixPrefix)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		CleanupListener(log, address)
	}
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0775)
		if err != nil {
			return nil, err
		}
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	mode := os.FileMode(0700)
	root, _ := utils.HasRoot() // error ignored
	if !root {
		// allow group access when not running as root
		mode = os.FileMode(0770)
	}
	err = os.Chmod(path, mode)
	if err != nil {
		// failed to set permissions (close listener)
		lis.Close()
		return nil, err
	}
	return lis, nil
}

// CleanupListener removes listener file if domain socket
// Shared for control and beats comms sockets
func CleanupListener(log *logger.Logger, address string) {
	path := strings.TrimPrefix(address, schemeUnixPrefix)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Debug("%s", errors.New(err, fmt.Sprintf("Failed to cleanup %s", path), errors.TypeFilesystem, errors.M("path", path)))
	}
}
