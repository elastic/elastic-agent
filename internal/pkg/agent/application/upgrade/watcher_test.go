// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestWatcher_CannotConnect(t *testing.T) {
	// timeout ensures that if it doesn't work; it doesn't block forever
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errCh := make(chan error)
	logger, _ := loggertest.New("watcher")
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
	logger, _ := loggertest.New("watcher")
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

func TestWatcher_PIDChange(t *testing.T) {
	// timeout ensures that if it doesn't work; it doesn't block forever
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errCh := make(chan error)
	logger, _ := loggertest.New("watcher")
	w := NewAgentWatcher(errCh, logger, 1*time.Millisecond)

	// error on watch (counts as lost connect)
	mockHandler := func(srv cproto.ElasticAgentControl_StateWatchServer) error {
		// starts with PID 1
		err := srv.Send(&cproto.StateResponse{
			Info: &cproto.StateAgentInfo{
				Pid: 1,
			},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		// now with PID 2
		err = srv.Send(&cproto.StateResponse{
			Info: &cproto.StateAgentInfo{
				Pid: 2,
			},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		// now with PID 3
		err = srv.Send(&cproto.StateResponse{
			Info: &cproto.StateAgentInfo{
				Pid: 3,
			},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		// now with PID 4
		err = srv.Send(&cproto.StateResponse{
			Info: &cproto.StateAgentInfo{
				Pid: 4,
			},
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
		assert.ErrorIs(t, err, ErrLostConnection)
	}
}

func TestWatcher_PIDChangeSuccess(t *testing.T) {
	// test tests for success, which only happens when no error comes in
	// during this time period
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// buffered channel so we can drain after we send everything
	errCh := make(chan error, 10)
	logger, _ := loggertest.New("watcher")
	w := NewAgentWatcher(errCh, logger, 1*time.Millisecond)

	// error on watch (counts as lost connect)
	sentEverything := make(chan struct{})
	mockHandler := func(srv cproto.ElasticAgentControl_StateWatchServer) error {
		// starts with PID 1
		err := srv.Send(&cproto.StateResponse{
			Info: &cproto.StateAgentInfo{
				Pid: 1,
			},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		// now with PID 2
		err = srv.Send(&cproto.StateResponse{
			Info: &cproto.StateAgentInfo{
				Pid: 2,
			},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		// now with PID 3
		err = srv.Send(&cproto.StateResponse{
			Info: &cproto.StateAgentInfo{
				Pid: 3,
			},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		// still with PID 3
		err = srv.Send(&cproto.StateResponse{
			Info: &cproto.StateAgentInfo{
				Pid: 3,
			},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		// still with PID 3
		err = srv.Send(&cproto.StateResponse{
			Info: &cproto.StateAgentInfo{
				Pid: 3,
			},
			State:   cproto.State_HEALTHY,
			Message: "healthy",
		})
		if err != nil {
			return err
		}
		// close the channel to signify that we sent everything
		close(sentEverything)
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
	case <-sentEverything:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for everything to be sent")
		return
	}

	for {
		select {
		case err := <-errCh:
			assert.NoError(t, err, "error should not have been reported")
		case <-time.After(1 * time.Second):
			return
		}
	}
}

// TestWatcher_GracefulShutdownWithPreloadedLostCounter is a regression test
// for the race where watch()'s deferred close(errChan) fires before
// AgentWatcher.Run() exits, causing a panic (send on closed channel) when the
// context.Canceled error from gRPC pushes lostCounter past statusLossesAllowed.
//
// The test preloads lostCounter to statusLossesAllowed via PID changes, then
// cancels the context (simulating grace-period expiry) and asserts that no
// error is written to errChan — i.e. the watcher exits cleanly rather than
// treating the expected shutdown as a connection failure.
func TestWatcher_GracefulShutdownWithPreloadedLostCounter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Buffered so that a bug (send of ErrLostConnection) lands here instead of
	// panicking, allowing the test to fail with a descriptive assertion.
	errCh := make(chan error, 10)
	logger, _ := loggertest.New("watcher")
	// Long checkInterval to prevent reconnect races during the test.
	w := NewAgentWatcher(errCh, logger, 500*time.Millisecond)

	mockHandler := func(srv cproto.ElasticAgentControl_StateWatchServer) error {
		// Three PIDs: first sets lastPid, next two each increment lostCounter.
		for _, pid := range []int32{1, 2, 3} {
			if err := srv.Send(&cproto.StateResponse{
				Info:    &cproto.StateAgentInfo{Pid: pid},
				State:   cproto.State_HEALTHY,
				Message: "healthy",
			}); err != nil {
				return err
			}
		}
		<-ctx.Done()
		return nil
	}
	md := &mockDaemon{watch: mockHandler}
	require.NoError(t, md.Start())
	defer md.Stop()

	w.agentClient = md.Client()
	go w.Run(ctx)

	// Wait until the watcher has processed both PID changes and lostCounter
	// reaches the threshold. The test file is in the same package so it can
	// read the private field directly.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, int32(statusLossesAllowed), w.lostCounter.Load())
	}, 3*time.Second, 5*time.Millisecond)

	// Cancel the context, simulating grace-period expiry triggering watch()'s
	// deferred cleanup. Before the fix, Run() would increment lostCounter to 3
	// (> statusLossesAllowed=2) and send ErrLostConnection on errCh (and panic
	// if errCh had been closed). After the fix, Run() detects ctx.Err() != nil
	// and returns cleanly.
	cancel()

	select {
	case err := <-errCh:
		require.NoError(t, err, "watcher must not report an error when context is canceled")
	case <-time.After(500 * time.Millisecond):
		// clean exit — expected
	}
}

func TestWatcher_AgentError(t *testing.T) {
	// timeout ensures that if it doesn't work; it doesn't block forever
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errCh := make(chan error)
	logger, _ := loggertest.New("watcher")
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
	// Success only happens when no error comes in during this time period
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	errCh := make(chan error)
	log, obs := loggertest.New("watcher")
	defer func() {
		if t.Failed() {
			loggertest.PrintObservedLogs(obs.TakeAll(), t.Log)
		}
	}()
	w := NewAgentWatcher(errCh, log, 100*time.Millisecond)

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
	require.NoError(t, mock.Start(), "could not start mock agent daemon")
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
	logger, _ := loggertest.New("watcher")
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
	logger, _ := loggertest.New("watcher")
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
	logger, _ := loggertest.New("watcher")
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
		_ = srv.Serve(lis)
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
