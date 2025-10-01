// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package utils

import (
	"fmt"
	"net"
)

// for testing purposes
var netListen = net.Listen

// FindRandomTCPPort finds a random available TCP port on the localhost interface.
func FindRandomTCPPort() (int, error) {
	l, err := netListen("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	port := l.Addr().(*net.TCPAddr).Port
	err = l.Close()
	if err != nil {
		return 0, err
	}
	if port == 0 {
		return 0, fmt.Errorf("failed to find random port")
	}

	return port, nil
}
