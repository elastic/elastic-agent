// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockListener struct {
	port int
}

func (l *mockListener) Accept() (net.Conn, error) {
	panic("not implemented")
}

func (l *mockListener) Close() error {
	return nil
}

func (l *mockListener) Addr() net.Addr {
	return &net.TCPAddr{
		Port: l.port,
	}
}

func TestFindRandomPort(t *testing.T) {
	port, err := findRandomTCPPort()
	require.NoError(t, err)
	require.NotEqual(t, 0, port)

	defer func() {
		netListen = net.Listen
	}()

	netListen = func(string, string) (net.Listener, error) {
		return nil, errors.New("some error")
	}
	_, err = findRandomTCPPort()
	require.Error(t, err)

	netListen = func(string, string) (net.Listener, error) {
		return &mockListener{0}, nil
	}
	_, err = findRandomTCPPort()
	require.Error(t, err)
}
