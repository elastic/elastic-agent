// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func createListener(path string) (net.Listener, error) {
	if !strings.HasPrefix(path, "unix://") {
		return nil, fmt.Errorf("listener path must start with unix://; got %s", path)
	}
	path = strings.TrimPrefix(path, "unix://")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		os.Remove(path)
	}
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0750)
		if err != nil {
			return nil, err
		}
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return lis, err
}
