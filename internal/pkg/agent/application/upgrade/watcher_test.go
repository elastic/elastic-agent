// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestWatcher_CannotConnect(t *testing.T) {
	// timeout ensures that if it doesn't work; it doesn't block forever
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errCh := make(chan error)
	logger, _ := logger.NewTesting("watcher")
	w := NewAgentWatcher(errCh, logger, 1*time.Millisecond)
	go w.Run(ctx)

	select {
	case <-ctx.Done():
		require.NoError(t, ctx.Err())
	case err := <-errCh:
		assert.ErrorIs(t, err, ErrCannotConnect)
	}
}

func TestWatcher_LostConnection(t *testing.T) {
	// timeout ensures that if it doesn't work; it doesn't block forever
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errCh := make(chan error)
	logger, _ := logger.NewTesting("watcher")
	w := NewAgentWatcher(errCh, logger, 1*time.Millisecond)

	// error on watch (counts as lost connect)
	mockHandler := func(srv cproto.ElasticAgentControl_StateWatchServer) error {
		return fmt.Errorf("forced error")
	}
	mock := &mockDaemon{watch: mockHandler}
	require.NoError(t, mock.Start())
	defer mock.Stop()

	// set client to mock; before running
	w.agentClient = mock.Client()
	go w.Run(ctx)

	select {
	case <-ctx.Done():
		require.NoError(t, ctx.Err())
	case err := <-errCh:
		assert.ErrorIs(t, err, ErrLostConnection)
	}
}

func TestWatcher_AgentError(t *testing.T) {
	// timeout ensures that if it doesn't work; it doesn't block forever
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errCh := make(chan error)
	logger, _ := logger.NewTesting("watcher")
	w := NewAgentWatcher(errCh, logger, 100*time.Millisecond)

	// reports only an error state, triggers failed
	mockHandler := func(srv cproto.ElasticAgentControl_StateWatchServer) error {
		err := srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_FAILED,
			Message: "force failure",
		})
		if err != nil {
			return err
		}
		// keep open until end (exiting will count as a lost connection)
		<-ctx.Done()
		return nil
	}
	mock := &mockDaemon{watch: mockHandler}
	require.NoError(t, mock.Start())
	defer mock.Stop()

	// set client to mock; before running
	w.agentClient = mock.Client()
	go w.Run(ctx)

	select {
	case <-ctx.Done():
		require.NoError(t, ctx.Err())
	case err := <-errCh:
		assert.ErrorIs(t, err, ErrAgentStatusFailed)
	}
}

func TestWatcher_AgentErrorQuick(t *testing.T) {
	// test tests for success, which only happens when no error comes in
	// during this time period
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	errCh := make(chan error)
	logger, _ := logger.NewTesting("watcher")
	w := NewAgentWatcher(errCh, logger, 100*time.Millisecond)

	// reports an error state, followed by a healthy state (should not error)
	mockHandler := func(srv cproto.ElasticAgentControl_StateWatchServer) error {
		err := srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_FAILED,
			Message: "force failure",
		})
		if err != nil {
			return err
		}
		err = srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		// keep open until end (exiting will count as a lost connection)
		<-ctx.Done()
		return nil
	}
	mock := &mockDaemon{watch: mockHandler}
	require.NoError(t, mock.Start())
	defer mock.Stop()

	// set client to mock; before running
	w.agentClient = mock.Client()
	go w.Run(ctx)

	select {
	case <-ctx.Done():
		require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
	case err := <-errCh:
		assert.NoError(t, err, "error should not have been reported")
	}
}

func TestWatcher_ComponentError(t *testing.T) {
	// timeout ensures that if it doesn't work; it doesn't block forever
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errCh := make(chan error)
	logger, _ := logger.NewTesting("watcher")
	w := NewAgentWatcher(errCh, logger, 100*time.Millisecond)

	// reports only an error state, triggers failed
	mockHandler := func(srv cproto.ElasticAgentControl_StateWatchServer) error {
		err := srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
			Components: []*cproto.ComponentState{
				{
					Id:      "component-0",
					Name:    "component-0",
					State:   cproto.State_HEALTHY,
					Message: "healthy",
				},
				{
					Id:      "component-1",
					Name:    "component-1",
					State:   cproto.State_FAILED,
					Message: "force error",
				},
				{
					Id:      "component-2",
					Name:    "component-2",
					State:   cproto.State_HEALTHY,
					Message: "healthy",
				},
			},
		})
		if err != nil {
			return err
		}
		// keep open until end (exiting will count as a lost connection)
		<-ctx.Done()
		return nil
	}
	mock := &mockDaemon{watch: mockHandler}
	require.NoError(t, mock.Start())
	defer mock.Stop()

	// set client to mock; before running
	w.agentClient = mock.Client()
	go w.Run(ctx)

	select {
	case <-ctx.Done():
		require.NoError(t, ctx.Err())
	case err := <-errCh:
		assert.ErrorIs(t, err, ErrAgentComponentFailed)
	}
}

func TestWatcher_ComponentErrorQuick(t *testing.T) {
	// test tests for success, which only happens when no error comes in
	// during this time period
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	errCh := make(chan error)
	logger, _ := logger.NewTesting("watcher")
	w := NewAgentWatcher(errCh, logger, 100*time.Millisecond)

	// reports an error state, followed by a healthy state (should not error)
	mockHandler := func(srv cproto.ElasticAgentControl_StateWatchServer) error {
		err := srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
			Components: []*cproto.ComponentState{
				{
					Id:      "component-0",
					Name:    "component-0",
					State:   cproto.State_HEALTHY,
					Message: "healthy",
				},
				{
					Id:      "component-1",
					Name:    "component-1",
					State:   cproto.State_FAILED,
					Message: "force error",
				},
				{
					Id:      "component-2",
					Name:    "component-2",
					State:   cproto.State_HEALTHY,
					Message: "healthy",
				},
			},
		})
		if err != nil {
			return err
		}
		err = srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
			Components: []*cproto.ComponentState{
				{
					Id:      "component-0",
					Name:    "component-0",
					State:   cproto.State_HEALTHY,
					Message: "healthy",
				},
				{
					Id:      "component-1",
					Name:    "component-1",
					State:   cproto.State_HEALTHY,
					Message: "healthy",
				},
				{
					Id:      "component-2",
					Name:    "component-2",
					State:   cproto.State_HEALTHY,
					Message: "healthy",
				},
			},
		})
		if err != nil {
			return err
		}
		// keep open until end (exiting will count as a lost connection)
		<-ctx.Done()
		return nil
	}
	mock := &mockDaemon{watch: mockHandler}
	require.NoError(t, mock.Start())
	defer mock.Stop()

	// set client to mock; before running
	w.agentClient = mock.Client()
	go w.Run(ctx)

	select {
	case <-ctx.Done():
		require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
	case err := <-errCh:
		assert.NoError(t, err, "error should not have been reported")
	}
}

func TestWatcher_AgentErrorFlipFlop(t *testing.T) {
	// timeout ensures that if it doesn't work; it doesn't block forever
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errCh := make(chan error)
	logger, _ := logger.NewTesting("watcher")
	w := NewAgentWatcher(errCh, logger, 300*time.Millisecond)

	// reports only an error state, triggers failed
	mockHandler := func(srv cproto.ElasticAgentControl_StateWatchServer) error {
		err := srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		err = srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_FAILED,
			Message: "force failure",
		})
		if err != nil {
			return err
		}
		err = srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		err = srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_FAILED,
			Message: "force failure",
		})
		if err != nil {
			return err
		}
		err = srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		err = srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_FAILED,
			Message: "force failure",
		})
		if err != nil {
			return err
		}
		err = srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		err = srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_FAILED,
			Message: "force failure",
		})
		if err != nil {
			return err
		}
		err = srv.Send(&cproto.StateResponse{
			Info:    &cproto.StateAgentInfo{},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		// keep open until end (exiting will count as a lost connection)
		<-ctx.Done()
		return nil
	}
	mock := &mockDaemon{watch: mockHandler}
	require.NoError(t, mock.Start())
	defer mock.Stop()

	// set client to mock; before running
	w.agentClient = mock.Client()
	go w.Run(ctx)

	select {
	case <-ctx.Done():
		require.NoError(t, ctx.Err())
	case err := <-errCh:
		assert.ErrorIs(t, err, ErrAgentFlipFlopFailed)
	}
}

type mockStateWatch func(srv cproto.ElasticAgentControl_StateWatchServer) error

type mockDaemon struct {
	cproto.UnimplementedElasticAgentControlServer

	port   int
	server *grpc.Server

	watch mockStateWatch
}

func (s *mockDaemon) Start(opt ...grpc.ServerOption) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return err
	}
	s.port = lis.Addr().(*net.TCPAddr).Port
	srv := grpc.NewServer(opt...)
	s.server = srv
	cproto.RegisterElasticAgentControlServer(s.server, s)
	go func() {
		srv.Serve(lis)
	}()
	return nil
}

func (s *mockDaemon) Stop() {
	if s.server != nil {
		s.server.Stop()
		s.server = nil
	}
}

func (s *mockDaemon) Client() client.Client {
	return client.New(client.WithAddress(fmt.Sprintf("http://localhost:%d", s.port)))
}

func (s *mockDaemon) StateWatch(_ *cproto.Empty, srv cproto.ElasticAgentControl_StateWatchServer) error {
	return s.watch(srv)
}
