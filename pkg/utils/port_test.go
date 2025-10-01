// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package utils

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindRandomPort(t *testing.T) {
	port, err := FindRandomTCPPort()
	require.NoError(t, err)
	require.NotEqual(t, 0, port)

	defer func() {
		netListen = net.Listen
	}()

	netListen = func(string, string) (net.Listener, error) {
		return nil, errors.New("some error")
	}
	_, err = FindRandomTCPPort()
	require.Error(t, err, "failed to find random port")
}
