// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
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

func Test_selectWatcherExecutable(t *testing.T) {
	type args struct {
		previous agentInstall
		current  agentInstall
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Simple upgrade, we should launch the new (current) watcher",
			args: args{
				previous: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-somehash"),
				},
				current: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(4, 5, 6, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-4.5.6-someotherhash"),
				},
			},
			want: filepath.Join("data", "elastic-agent-4.5.6-someotherhash"),
		},
		{
			name: "Simple downgrade, we should launch the currently installed (previous) watcher",
			args: args{
				previous: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(4, 5, 6, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-4.5.6-someotherhash"),
				},
				current: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-somehash"),
				},
			},
			want: filepath.Join("data", "elastic-agent-4.5.6-someotherhash"),
		},
		{
			name: "Upgrade from snapshot to released version, we should launch the new (current) watcher",
			args: args{
				previous: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-somehash"),
				},
				current: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-someotherhash"),
				},
			},
			want: filepath.Join("data", "elastic-agent-1.2.3-someotherhash"),
		},
		{
			name: "Downgrade from released version to SNAPSHOT, we should launch the currently installed (previous) watcher",
			args: args{
				previous: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-somehash"),
				},
				current: agentInstall{
					parsedVersion: agtversion.NewParsedSemVer(1, 2, 3, "SNAPSHOT", ""),
					versionedHome: filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-someotherhash"),
				},
			},

			want: filepath.Join("data", "elastic-agent-1.2.3-somehash"),
		},
	}
	// Just need a top dir path. This test does not make any operation on the filesystem, so a temp dir path is as good as any
	fakeTopDir := filepath.Join(t.TempDir(), "Elastic", "Agent")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, paths.BinaryPath(filepath.Join(fakeTopDir, tt.want), agentName), selectWatcherExecutable(fakeTopDir, tt.args.previous, tt.args.current), "selectWatcherExecutable(%v, %v)", tt.args.previous, tt.args.current)
		})
	}
}

func TestWaitForWatcher(t *testing.T) {
	wantErrWatcherNotStarted := func(t assert.TestingT, err error, i ...interface{}) bool {
		return assert.ErrorIs(t, err, ErrWatcherNotStarted, i)
	}

	tests := []struct {
		name                string
		states              []details.State
		stateChangeInterval time.Duration
		cancelWaitContext   bool
		wantErr             assert.ErrorAssertionFunc
	}{
		{
			name:                "Happy path: watcher is watching already",
			states:              []details.State{details.StateWatching},
			stateChangeInterval: 1 * time.Millisecond,
			wantErr:             assert.NoError,
		},
		{
			name:                "Sad path: watcher is never starting",
			states:              []details.State{details.StateReplacing},
			stateChangeInterval: 1 * time.Millisecond,
			cancelWaitContext:   true,
			wantErr:             wantErrWatcherNotStarted,
		},
		{
			name: "Runaround path: marker is jumping around and landing on watching",
			states: []details.State{
				details.StateRequested,
				details.StateScheduled,
				details.StateDownloading,
				details.StateExtracting,
				details.StateReplacing,
				details.StateRestarting,
				details.StateWatching,
			},
			stateChangeInterval: 1 * time.Millisecond,
			wantErr:             assert.NoError,
		},
		{
			name:                "Timeout: marker is never created",
			states:              nil,
			stateChangeInterval: 1 * time.Millisecond,
			cancelWaitContext:   true,
			wantErr:             wantErrWatcherNotStarted,
		},
		{
			name: "Timeout2: state doesn't get there in time",
			states: []details.State{
				details.StateRequested,
				details.StateScheduled,
				details.StateDownloading,
				details.StateExtracting,
				details.StateReplacing,
				details.StateRestarting,
			},

			stateChangeInterval: 1 * time.Millisecond,
			cancelWaitContext:   true,
			wantErr:             wantErrWatcherNotStarted,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deadline, ok := t.Deadline()
			if !ok {
				deadline = time.Now().Add(5 * time.Second)
			}
			testCtx, testCancel := context.WithDeadline(context.Background(), deadline)
			defer testCancel()

			tmpDir := t.TempDir()
			updMarkerFilePath := filepath.Join(tmpDir, markerFilename)

			waitContext, waitCancel := context.WithCancel(testCtx)
			defer waitCancel()

			fakeTimeout := 30 * time.Second

			// in order to take timing out of the equation provide a context that we can cancel manually
			// still assert that the parent context and timeout passed are correct
			var createContextFunc createContextWithTimeout = func(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
				assert.Same(t, testCtx, ctx, "parent context should be the same as the waitForWatcherCall")
				assert.Equal(t, fakeTimeout, timeout, "timeout used in new context should be the same as testcase")

				return waitContext, waitCancel
			}

			if len(tt.states) > 0 {
				initialState := tt.states[0]
				writeState(t, updMarkerFilePath, initialState)
			}

			wg := new(sync.WaitGroup)

			var furtherStates []details.State
			if len(tt.states) > 1 {
				// we have more states to produce
				furtherStates = tt.states[1:]
			}

			wg.Add(1)

			// worker goroutine: writes out additional states while the test is blocked on waitOnWatcher() call and expires
			// the wait context if cancelWaitContext is set to true. Timing of the goroutine is driven by stateChangeInterval.
			go func() {
				defer wg.Done()
				tick := time.NewTicker(tt.stateChangeInterval)
				defer tick.Stop()
				for _, state := range furtherStates {
					select {
					case <-testCtx.Done():
						return
					case <-tick.C:
						writeState(t, updMarkerFilePath, state)
					}
				}
				if tt.cancelWaitContext {
					<-tick.C
					waitCancel()
				}
			}()

			log, _ := loggertest.New(tt.name)

			tt.wantErr(t, waitForWatcherWithTimeoutCreationFunc(testCtx, log, updMarkerFilePath, fakeTimeout, createContextFunc), fmt.Sprintf("waitForWatcher %s, %v, %s, %s)", updMarkerFilePath, tt.states, tt.stateChangeInterval, fakeTimeout))

			// wait for goroutines to finish
			wg.Wait()
		})
	}
}

func writeState(t *testing.T, path string, state details.State) {
	ms := newMarkerSerializer(&UpdateMarker{
		Version:           "version",
		Hash:              "hash",
		VersionedHome:     "versionedHome",
		UpdatedOn:         time.Now(),
		PrevVersion:       "prev_version",
		PrevHash:          "prev_hash",
		PrevVersionedHome: "prev_versionedhome",
		Acked:             false,
		Action:            nil,
		Details: &details.Details{
			TargetVersion: "version",
			State:         state,
			ActionID:      "",
			Metadata:      details.Metadata{},
		},
	})

	bytes, err := yaml.Marshal(ms)
	if assert.NoError(t, err, "error marshaling the test upgrade marker") {
		err = os.WriteFile(path, bytes, 0770)
		assert.NoError(t, err, "error writing out the test upgrade marker")
	}
}

// TestTakeOverWatcher verifies that takeOverWatcher behaves within expectations.
// This test cannot run in parallel because it deals with launching test processes and verifying their state.
// In case of aggressive PID reuse along with parallel execution, this test could kill "innocent" processes
func TestTakeOverWatcher(t *testing.T) {

	type setupFunc func(t *testing.T, workdir string, mockWatcherGrappler *mockWatcherGrappler)
	type assertFunc func(t *testing.T, workdir string, appLocker *filelock.AppLocker)

	testcases := []struct {
		name               string
		setup              setupFunc
		wantErr            assert.ErrorAssertionFunc
		assertPostTakeover assertFunc
	}{
		{
			name: "no contention for watcher applocker",
			setup: func(t *testing.T, workdir string, mockWatcherGrappler *mockWatcherGrappler) {
				// nothing to do here
			},
			wantErr: assert.NoError,
			assertPostTakeover: func(t *testing.T, workdir string, appLocker *filelock.AppLocker) {
				assert.NotNil(t, appLocker, "appLocker should not be nil")
				assert.FileExists(t, filepath.Join(workdir, watcherApplockerFileName))
			},
		},
		{
			name: "contention with a process that can be taken down: no error",
			setup: func(t *testing.T, workdir string, mockWatcherGrappler *mockWatcherGrappler) {
				// create and lock an applocker
				locker := filelock.NewAppLocker(workdir, watcherApplockerFileName)
				err := locker.TryLock()
				require.NoError(t, err, "error setting up the applocker")
				mockWatcherGrappler.EXPECT().TakeDownWatcher(mock.Anything, mock.Anything).Run(func(_ context.Context, _ *logp.Logger) {
					unlockErr := locker.Unlock()
					assert.NoError(t, unlockErr, "error unlocking the applocker")
				}).Return(nil)

				// add a cleanup to unlock the applocker at the end of the test anyway in case of failures
				t.Cleanup(func() {
					_ = locker.Unlock()
				})
			},
			wantErr: assert.NoError,
			assertPostTakeover: func(t *testing.T, workdir string, appLocker *filelock.AppLocker) {
				assert.NotNil(t, appLocker, "appLocker should not be nil")
				assert.FileExists(t, filepath.Join(workdir, watcherApplockerFileName))
			},
		},
		{
			name: "contention with a process that can be taken down with multiple attempts: no error",
			setup: func(t *testing.T, workdir string, mockWatcherGrappler *mockWatcherGrappler) {
				// create and lock an applocker
				locker := filelock.NewAppLocker(workdir, watcherApplockerFileName)
				err := locker.TryLock()
				require.NoError(t, err, "error setting up the applocker")
				mockWatcherGrappler.EXPECT().TakeDownWatcher(mock.Anything, mock.Anything).Return(fmt.Errorf("some takedown error")).Once()
				mockWatcherGrappler.EXPECT().TakeDownWatcher(mock.Anything, mock.Anything).Run(func(_ context.Context, _ *logp.Logger) {
					unlockErr := locker.Unlock()
					assert.NoError(t, unlockErr, "error unlocking the applocker")
				}).Return(nil)

				// add a cleanup to unlock the applocker at the end of the test anyway in case of failures
				t.Cleanup(func() {
					_ = locker.Unlock()
				})
			},
			wantErr: assert.NoError,
			assertPostTakeover: func(t *testing.T, workdir string, appLocker *filelock.AppLocker) {
				assert.NotNil(t, appLocker, "appLocker should not be nil")
				assert.FileExists(t, filepath.Join(workdir, watcherApplockerFileName))
			},
		},
		{
			name: "contention with a process that cannot be taken down: error is returned by takeOverWatcher",
			setup: func(t *testing.T, workdir string, mockWatcherGrappler *mockWatcherGrappler) {
				// create and lock an applocker
				locker := filelock.NewAppLocker(workdir, watcherApplockerFileName)
				err := locker.TryLock()
				require.NoError(t, err, "error setting up the applocker")

				// Expect the calls to applocker but do not release the lock
				mockWatcherGrappler.EXPECT().TakeDownWatcher(mock.Anything, mock.Anything).Return(nil)

				// add a cleanup to unlock the applocker at the end of the test anyway
				t.Cleanup(func() {
					_ = locker.Unlock()
				})
			},
			wantErr: assert.Error,
			assertPostTakeover: func(t *testing.T, workdir string, appLocker *filelock.AppLocker) {
				assert.Nil(t, appLocker, "appLocker should be nil")
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			workDir := t.TempDir()
			logger, logs := loggertest.New(t.Name())

			mockGrappler := newMockWatcherGrappler(t)
			tc.setup(t, workDir, mockGrappler)

			appLocker, err := takeOverWatcher(t.Context(), logger, mockGrappler, workDir, 10*time.Second, 500*time.Millisecond, 100*time.Millisecond)
			loggertest.PrintObservedLogs(logs.TakeAll(), t.Log)

			tc.wantErr(t, err)
			if appLocker != nil {
				defer func(appLocker *filelock.AppLocker) {
					unlockErr := appLocker.Unlock()
					assert.NoError(t, unlockErr, "error unlocking the app locker")
				}(appLocker)
			}
			if tc.assertPostTakeover != nil {
				tc.assertPostTakeover(t, workDir, appLocker)
			}
		})
	}

}
