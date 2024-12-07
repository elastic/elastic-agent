// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"log"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	clientmocks "github.com/elastic/elastic-agent/testing/mocks/pkg/control/v2/client"
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
		err = c.Connect(context.Background())
		assert.NoError(t, err)

		args := []string{"--skip-verify", "8.13.0"}
		streams := cli.NewIOStreams()
		cmd := newUpgradeCommandWithArgs(args, streams)
		cmd.SetContext(context.Background())

		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			c,
			client.AgentStateInfo{IsManaged: false},
			false,
			"",
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
		c.Disconnect()
	})

	t.Run("fail if fleet managed and unprivileged with --force flag", func(t *testing.T) {
		mockClient := clientmocks.NewClient(t)

		args := []string{"8.13.0"} // Version argument
		streams := cli.NewIOStreams()
		cmd := newUpgradeCommandWithArgs(args, streams)
		err := cmd.Flags().Set(flagForce, "true")
		if err != nil {
			log.Fatal(err)
		}
		cmd.SetContext(context.Background())

		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			mockClient,
			client.AgentStateInfo{
				IsManaged: true,
			},
			false,
			"",
		}

		err = upgradeCmdWithClient(commandInput)

		// Expect an error due to unprivileged fleet-managed mode
		assert.Error(t, err)
		assert.Contains(t, err.Error(), NonRootExecutionError.Error())
	})

	t.Run("fail if fleet managed privileged but no force flag", func(t *testing.T) {
		mockClient := clientmocks.NewClient(t)

		args := []string{"8.13.0"} // Version argument
		streams := cli.NewIOStreams()
		cmd := newUpgradeCommandWithArgs(args, streams)
		cmd.SetContext(context.Background())

		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			mockClient,
			client.AgentStateInfo{IsManaged: true},
			true,
			"",
		}

		err := upgradeCmdWithClient(commandInput)

		// Expect an error due to unprivileged fleet-managed mode
		assert.Error(t, err)
		assert.Contains(t, err.Error(), UnsupportedUpgradeError.Error())
	})

	t.Run("proceed with upgrade if fleet managed, privileged, --force is set", func(t *testing.T) {
		mockClient := clientmocks.NewClient(t)
		mockClient.EXPECT().State(mock.Anything).Return(&client.AgentState{State: cproto.State_HEALTHY}, nil)
		mockClient.EXPECT().Upgrade(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("mockVersion", nil)

		args := []string{"8.13.0"} // Version argument
		streams := cli.NewIOStreams()
		cmd := newUpgradeCommandWithArgs(args, streams)
		cmd.SetContext(context.Background())
		err := cmd.Flags().Set(flagForce, "true")
		if err != nil {
			log.Fatal(err)
		}

		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			mockClient,
			client.AgentStateInfo{IsManaged: true},
			true,
			"",
		}

		err = upgradeCmdWithClient(commandInput)

		assert.NoError(t, err)
	})
	t.Run("abort upgrade if the agent is fleet managed and skip-verify flag is set", func(t *testing.T) {
		mockClient := clientmocks.NewClient(t)

		args := []string{"8.13.0"} // Version argument
		streams := cli.NewIOStreams()

		cmd := newUpgradeCommandWithArgs(args, streams)
		cmd.SetContext(context.Background())
		err := cmd.Flags().Set(flagForce, "true")
		if err != nil {
			log.Fatal(err)
		}
		err = cmd.Flags().Set(flagSkipVerify, "true")
		if err != nil {
			log.Fatal(err)
		}

		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			mockClient,
			client.AgentStateInfo{IsManaged: true},
			true,
			"",
		}

		err = upgradeCmdWithClient(commandInput)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), SkipVerifyNotAllowedError.Error())
	})
	t.Run("abort upgrade if the agent is standalone, the user is unprivileged and skip-verify flag is set", func(t *testing.T) {
		mockClient := clientmocks.NewClient(t)

		args := []string{"8.13.0"} // Version argument
		streams := cli.NewIOStreams()

		cmd := newUpgradeCommandWithArgs(args, streams)
		cmd.SetContext(context.Background())
		err := cmd.Flags().Set(flagForce, "true")
		if err != nil {
			log.Fatal(err)
		}
		err = cmd.Flags().Set(flagSkipVerify, "true")
		if err != nil {
			log.Fatal(err)
		}
		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			mockClient,
			client.AgentStateInfo{IsManaged: false},
			false,
			"",
		}

		err = upgradeCmdWithClient(commandInput)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), SkipVerifyNotRootError.Error())
	})
	t.Run("proceed with upgrade if agent is standalone, user is privileged and skip-verify flag is set", func(t *testing.T) {
		mockClient := clientmocks.NewClient(t)
		mockClient.EXPECT().State(mock.Anything).Return(&client.AgentState{State: cproto.State_HEALTHY}, nil)
		mockClient.EXPECT().Upgrade(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("mockVersion", nil)

		args := []string{"8.13.0"} // Version argument
		streams := cli.NewIOStreams()

		cmd := newUpgradeCommandWithArgs(args, streams)
		cmd.SetContext(context.Background())
		err := cmd.Flags().Set(flagForce, "true")
		if err != nil {
			log.Fatal(err)
		}

		err = cmd.Flags().Set(flagSkipVerify, "true")
		if err != nil {
			log.Fatal(err)
		}

		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			mockClient,
			client.AgentStateInfo{IsManaged: false},
			true,
			"",
		}

		err = upgradeCmdWithClient(commandInput)
		assert.NoError(t, err)
	})
	t.Run("prevent upgrade if there is \"upgrades.disabled\" file in the config directory", func(t *testing.T) {
		mockClient := clientmocks.NewClient(t)

		// Here we are creating the upgrade disabled file in the current directory.
		// We have to set the topPath in the input struct to "" for this test to
		// work
		file, err := os.Create(upgradeDisabledFile)
		if err != nil {
			t.Fatalf("error creating test file: %s", err.Error())
		}
		err = file.Close()
		if err != nil {
			t.Fatalf("error closing the test file: %s", err.Error())
		}

		defer func(t *testing.T) {
			err := os.Remove(upgradeDisabledFile)
			if err != nil {
				t.Fatalf("error removing the test file: %s", err.Error())
			}
		}(t)

		args := []string{"8.13.0"} // Version argument
		streams := cli.NewIOStreams()

		cmd := newUpgradeCommandWithArgs(args, streams)
		cmd.SetContext(context.Background())
		err = cmd.Flags().Set(flagForce, "true")
		if err != nil {
			log.Fatal(err)
		}
		err = cmd.Flags().Set(flagSkipVerify, "true")
		if err != nil {
			log.Fatal(err)
		}
		commandInput := &upgradeInput{
			streams,
			cmd,
			args,
			mockClient,
			client.AgentStateInfo{IsManaged: false},
			false,
			"",
		}

		err = upgradeCmdWithClient(commandInput)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), UpgradeDisabledError.Error())
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
