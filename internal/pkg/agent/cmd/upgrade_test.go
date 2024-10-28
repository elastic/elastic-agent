// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	mockinfo "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/agent/application/info"
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
		mockAgentInfo := mockinfo.NewAgent(t)
		mockAgentInfo.EXPECT().IsStandalone().Return(true)
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
		cmd.SetContext(context.Background())

		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			c,
			mockAgentInfo,
			nil,
		}

		// the upgrade command will hang until the server shut down
		go func() {
			err = upgradeCmdWithClient(commandInput)
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
	t.Run("fail if fleet managed and unprivileged", func(t *testing.T) {
		var wg sync.WaitGroup
		// Set up mock TCP server for gRPC connection
		tcpServer, err := net.Listen("tcp", "127.0.0.1:")
		require.NoError(t, err)
		defer tcpServer.Close()

		s := grpc.NewServer()

		// Define mock server and agent information
		upgradeCh := make(chan struct{})
		mock := &mockServer{upgradeStop: upgradeCh}
		mockAgentInfo := mockinfo.NewAgent(t)
		mockAgentInfo.EXPECT().IsStandalone().Return(false) // Simulate fleet-managed agent
		mockAgentInfo.EXPECT().Unprivileged().Return(true)  // Simulate unprivileged mode
		cproto.RegisterElasticAgentControlServer(s, mock)

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Serve(tcpServer)
			assert.NoError(t, err)
		}()

		// Create client and command
		c := client.New(client.WithAddress("http://" + tcpServer.Addr().String()))
		args := []string{"8.13.0"} // Version argument
		streams := cli.NewIOStreams()
		cmd := newUpgradeCommandWithArgs(args, streams)
		cmd.SetContext(context.Background())

		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			c,
			mockAgentInfo,
			nil,
		}

		term := make(chan int)
		wg.Add(1)
		// Execute upgrade command and validate shouldUpgrade error
		go func() {
			defer wg.Done()
			err = upgradeCmdWithClient(commandInput)

			// Expect an error due to unprivileged fleet-managed mode
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "upgrade command needs to be executed as root for fleet managed agents")

			// Verify counter has not incremented since upgrade should not proceed
			counter := atomic.LoadInt32(&mock.upgrades)
			assert.Equal(t, int32(0), counter, "server should not have handled any upgrades")
			close(term)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-term
			s.Stop()
		}()

		wg.Wait()
	})

	t.Run("fail if fleet managed privileged but no force flag", func(t *testing.T) {
		var wg sync.WaitGroup
		// Set up mock TCP server for gRPC connection
		tcpServer, err := net.Listen("tcp", "127.0.0.1:")
		require.NoError(t, err)
		defer tcpServer.Close()

		s := grpc.NewServer()

		// Define mock server and agent information
		mock := &mockServer{}
		mockAgentInfo := mockinfo.NewAgent(t)
		mockAgentInfo.EXPECT().IsStandalone().Return(false) // Simulate fleet-managed agent
		mockAgentInfo.EXPECT().Unprivileged().Return(false) // Simulate privileged mode
		cproto.RegisterElasticAgentControlServer(s, mock)

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Serve(tcpServer)
			assert.NoError(t, err)
		}()

		// Create client and command
		c := client.New(client.WithAddress("http://" + tcpServer.Addr().String()))
		args := []string{"8.13.0"} // Version argument
		streams := cli.NewIOStreams()
		cmd := newUpgradeCommandWithArgs(args, streams)
		cmd.SetContext(context.Background())

		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			c,
			mockAgentInfo,
			nil,
		}

		term := make(chan int)
		wg.Add(1)
		// Execute upgrade command and validate shouldUpgrade error
		go func() {
			defer wg.Done()
			err = upgradeCmdWithClient(commandInput)

			// Expect an error due to unprivileged fleet-managed mode
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "upgrading fleet managed agents is not supported")

			// Verify counter has not incremented since upgrade should not proceed
			counter := atomic.LoadInt32(&mock.upgrades)
			assert.Equal(t, int32(0), counter, "server should not have handled any upgrades")
			close(term)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-term
			s.Stop()
		}()

		wg.Wait()
	})
	t.Run("abort upgrade if fleet managed, privileged, --force is set, and user does not confirm", func(t *testing.T) {
		var wg sync.WaitGroup
		// Set up mock TCP server for gRPC connection
		tcpServer, err := net.Listen("tcp", "127.0.0.1:")
		require.NoError(t, err)
		defer tcpServer.Close()

		s := grpc.NewServer()

		// Define mock server and agent information
		mock := &mockServer{}
		mockAgentInfo := mockinfo.NewAgent(t)
		mockAgentInfo.EXPECT().IsStandalone().Return(false) // Simulate fleet-managed agent
		mockAgentInfo.EXPECT().Unprivileged().Return(false) // Simulate privileged mode
		cproto.RegisterElasticAgentControlServer(s, mock)

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Serve(tcpServer)
			assert.NoError(t, err)
		}()

		// Create client and command
		c := client.New(client.WithAddress("http://" + tcpServer.Addr().String()))
		args := []string{"8.13.0"} // Version argument
		streams := cli.NewIOStreams()
		cmd := newUpgradeCommandWithArgs(args, streams)
		cmd.SetContext(context.Background())
		err = cmd.Flags().Set("force", "true")
		if err != nil {
			log.Fatal(err)
		}

		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			c,
			mockAgentInfo,
			func(s string, b bool) (bool, error) {
				return false, nil
			},
		}

		term := make(chan int)
		wg.Add(1)
		// Execute upgrade command and validate shouldUpgrade error
		go func() {
			defer wg.Done()
			err = upgradeCmdWithClient(commandInput)

			// Expect an error because user does not confirm the upgrade
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "upgrade not confirmed")

			// Verify counter has not incremented since upgrade should not proceed
			counter := atomic.LoadInt32(&mock.upgrades)
			assert.Equal(t, int32(0), counter, "server should not have handled any upgrades")

			close(term)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-term
			s.Stop()
		}()

		wg.Wait()
	})
	t.Run("proceed with upgrade if fleet managed, privileged, --force is set, and user confirms upgrade", func(t *testing.T) {
		var wg sync.WaitGroup
		// Set up mock TCP server for gRPC connection
		tcpServer, err := net.Listen("tcp", "127.0.0.1:")
		require.NoError(t, err)
		defer tcpServer.Close()

		s := grpc.NewServer()

		// Define mock server and agent information
		upgradeCh := make(chan struct{})
		mock := &mockServer{upgradeStop: upgradeCh}
		mockAgentInfo := mockinfo.NewAgent(t)
		mockAgentInfo.EXPECT().IsStandalone().Return(false) // Simulate fleet-managed agent
		mockAgentInfo.EXPECT().Unprivileged().Return(false) // Simulate privileged mode
		cproto.RegisterElasticAgentControlServer(s, mock)

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Serve(tcpServer)
			assert.NoError(t, err)
		}()

		// Create client and command
		c := client.New(client.WithAddress("http://" + tcpServer.Addr().String()))
		args := []string{"8.13.0"} // Version argument
		streams := cli.NewIOStreams()
		cmd := newUpgradeCommandWithArgs(args, streams)
		cmd.SetContext(context.Background())
		err = cmd.Flags().Set("force", "true")
		if err != nil {
			log.Fatal(err)
		}

		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			c,
			mockAgentInfo,
			func(s string, b bool) (bool, error) {
				return true, nil
			},
		}

		term := make(chan int)
		wg.Add(1)
		// Execute upgrade command and validate that there are no errors
		go func() {
			defer wg.Done()
			err = upgradeCmdWithClient(commandInput)

			assert.NoError(t, err)

			// Verify counter is incremented
			counter := atomic.LoadInt32(&mock.upgrades)
			assert.Equal(t, int32(1), counter, "server should handle exactly one upgrade")

			close(term)
		}()

		close(upgradeCh)

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-term
			s.Stop()
		}()

		wg.Wait()
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
