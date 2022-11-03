// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func createListener(path string) (net.Listener, error) {
	if !strings.HasPrefix(path, "unix://") {
		return nil, fmt.Errorf("listener path must start with unix://")
	}
	path = strings.TrimPrefix(path, "unix://")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		os.Remove(path)
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return lis, err
}
