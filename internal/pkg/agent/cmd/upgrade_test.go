// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
)

func TestUpgradeCmd(t *testing.T) {
	t.Run("no error when connection gets interrupted", func(t *testing.T) {
		tcpServer, err := net.Listen("tcp", "127.0.0.1:")
		require.NoError(t, err)
		defer tcpServer.Close()

		s := grpc.NewServer()
		defer s.Stop()

		upgradeCh := make(chan struct{})
		mock := &mockServer{upgradeStop: upgradeCh}
		cproto.RegisterElasticAgentControlServer(s, mock)
		go func() {
			err := s.Serve(tcpServer)
			assert.NoError(t, err)
		}()

		clientCh := make(chan struct{})
		// use HTTP prefix for the dialer to use TCP, otherwise it's a unix socket/named pipe
		c := client.New(client.WithAddress("http://" + tcpServer.Addr().String()))
		args := []string{"--skip-verify", "8.13.0"}
		streams := cli.NewIOStreams()
		cmd := newUpgradeCommandWithArgs(args, streams)

		// the upgrade command will hang until the server shut down
		go func() {
			err = upgradeCmdWithClient(streams, cmd, args, c)
			assert.NoError(t, err)
			// verify that we actually talked to the server
			counter := atomic.LoadInt32(&mock.upgrades)
			assert.Equal(t, int32(1), counter, "server should have handled one upgrade")
			// unblock the further test execution
			close(clientCh)
		}()

		// we will know that the client reached the server watching the `mock.upgrades` counter
		require.Eventually(t, func() bool {
			counter := atomic.LoadInt32(&mock.upgrades)
			return counter > 0
		}, 5*time.Second, 100*time.Millisecond)

		// then we close the tcp server which is supposed to interrupt the connection
		s.Stop()
		// this stops the mock server
		close(upgradeCh)
		// this makes sure all client assertions are done
		<-clientCh
	})
}

type mockServer struct {
	cproto.ElasticAgentControlServer
	upgradeStop <-chan struct{}
	upgrades    int32
}

func (s *mockServer) Upgrade(ctx context.Context, r *cproto.UpgradeRequest) (resp *cproto.UpgradeResponse, err error) {
	atomic.AddInt32(&s.upgrades, 1)
	<-s.upgradeStop
	return nil, nil
}

func (s *mockServer) State(ctx context.Context, r *cproto.Empty) (resp *cproto.StateResponse, err error) {
	return &cproto.StateResponse{
		State: cproto.State_HEALTHY,
		Info:  &cproto.StateAgentInfo{},
	}, nil
}
