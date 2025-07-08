// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/core/authority"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

type agentInfoMock struct {
	agentID      string
	snapshot     bool
	version      string
	unprivileged bool
	isStandalone bool
}

func (a agentInfoMock) AgentID() string {
	return a.agentID
}
func (a agentInfoMock) Snapshot() bool {
	return a.snapshot
}

func (a agentInfoMock) Version() string {
	return a.version
}

func (a agentInfoMock) Unprivileged() bool {
	return a.unprivileged
}

func (a agentInfoMock) IsStandalone() bool {
	return a.isStandalone
}

func (a agentInfoMock) Headers() map[string]string                          { panic("implement me") }
func (a agentInfoMock) LogLevel() string                                    { panic("implement me") }
func (a agentInfoMock) RawLogLevel() string                                 { panic("implement me") }
func (a agentInfoMock) ReloadID(ctx context.Context) error                  { panic("implement me") }
func (a agentInfoMock) SetLogLevel(ctx context.Context, level string) error { panic("implement me") }
func (a agentInfoMock) ECSMetadata(l *logger.Logger) (*info.ECSMeta, error) { panic("implement me") }

func TestCheckinExpected(t *testing.T) {
	ca, err := authority.NewCA()
	require.NoError(t, err, "could not create CA")
	pair, err := ca.GeneratePair()
	require.NoError(t, err, "could not create certificate pair from CA")
	test := runtimeComm{
		listenAddr: "localhost",
		ca:         ca,
		name:       "a_name",
		token:      "a_token",
		cert:       pair,
		agentInfo: agentInfoMock{
			agentID:      "testagent",
			snapshot:     true,
			version:      "8.13.0+build1966-09-6",
			unprivileged: true,
		},
		checkinExpected:       make(chan *proto.CheckinExpected, 1),
		checkinObserved:       make(chan *proto.CheckinObserved),
		initCheckinObservedMx: sync.Mutex{},
	}

	expected := &proto.CheckinExpected{}
	observed := &proto.CheckinObserved{}
	test.CheckinExpected(expected, observed)

	got := <-test.checkinExpected
	require.True(t, got.AgentInfo.Unprivileged)
	t.Logf("got : %#v", got)

}

func TestRuntimeComm_WriteStartUpInfo_packageVersion(t *testing.T) {
	agentInfo := agentInfoMock{
		agentID:      "NCC-1701",
		snapshot:     true,
		version:      "8.13.0+build1966-09-6",
		unprivileged: true,
	}

	want := client.AgentInfo{
		ID:           agentInfo.AgentID(),
		Version:      agentInfo.Version(),
		Snapshot:     agentInfo.Snapshot(),
		Unprivileged: agentInfo.Unprivileged(),
	}

	ca, err := authority.NewCA()
	require.NoError(t, err, "could not create CA")
	pair, err := ca.GeneratePair()
	require.NoError(t, err, "could not create certificate pair from CA")

	c := runtimeComm{
		listenAddr: "localhost",
		ca:         ca,
		name:       "a_name",
		token:      "a_token",
		cert:       pair,
		agentInfo:  agentInfo,
	}

	buff := bytes.Buffer{}
	err = c.WriteStartUpInfo(&buff)
	require.NoError(t, err, "failed to write ConnInfo")

	clientv2, _, err := client.NewV2FromReader(&buff, client.VersionInfo{
		Name: "TestRuntimeComm_WriteConnInfo",
		Meta: nil,
	})
	require.NoError(t, err, "failed creating V2 client")

	assert.Equal(t, &want, clientv2.AgentInfo(),
		"agent info returned by client must match what has been written on command input")
}

func TestRuntimeComm_CheckinFlow(t *testing.T) {
	ca, caErr := authority.NewCA()
	require.NoError(t, caErr, "could not create CA")

	// remember we have slow runners in the CI
	const waitDuration = 20 * time.Second

	for _, tc := range []struct {
		name         string
		validateFlow func(t *testing.T, c *runtimeComm, srv *testServer)
	}{
		{
			name: "communicator destroyed before server checkin",
			validateFlow: func(t *testing.T, c *runtimeComm, srv *testServer) {
				initCheckinObserved := &proto.CheckinObserved{}
				// destroy the communicator before checkin
				c.destroy()
				err := c.checkin(srv, initCheckinObserved)
				s, ok := status.FromError(err)
				assert.True(t, ok, "error must be a gRPC status")
				assert.Equal(t, codes.Unavailable, s.Code(), "status code must be unavailable")
			},
		},
		{
			name: "communicator re-checkin after server checkin",
			validateFlow: func(t *testing.T, c *runtimeComm, srv *testServer) {
				initCheckinObserved := &proto.CheckinObserved{}
				// checkin the communicator
				errCh := make(chan error, 1)
				go func() {
					errCh <- c.checkin(srv, initCheckinObserved)
				}()

				// wait for the communicator to send the init checkin observed
				select {
				case err := <-errCh:
					t.Fatalf("checkin shouldn't returned an error: %v", err)
				case observed := <-c.CheckinObserved():
					assert.Equal(t, initCheckinObserved, observed, "checkin observed message must match the init checkin observed message")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the init checkin observed")
				}

				// re-checkin the communicator
				err := c.checkin(srv, &proto.CheckinObserved{})
				s, ok := status.FromError(err)
				assert.True(t, ok, "error must be a gRPC status")
				assert.Equal(t, codes.AlreadyExists, s.Code(), "status code must be already exists")

				// stop the server
				srv.stop(nil)
				select {
				case err = <-errCh:
					s, ok := status.FromError(err)
					assert.True(t, ok, "error must be a gRPC status")
					assert.Equal(t, codes.Unavailable, s.Code(), "status code must be unavailable")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}
			},
		},
		{
			name: "communicator destroyed before runtime reads init checkin observed",
			validateFlow: func(t *testing.T, c *runtimeComm, srv *testServer) {
				initCheckinObserved := &proto.CheckinObserved{}
				// checkin the communicator
				errCh := make(chan error, 1)
				go func() {
					errCh <- c.checkin(srv, initCheckinObserved)
				}()

				// cheat our way and check when the c.initCheckinObserved is set
				// to the initCheckinObserved which should always happen before the
				// communicator tries to send to the runtime the init checkin observed
				require.Eventually(t, func() bool {
					c.initCheckinObservedMx.Lock()
					defer c.initCheckinObservedMx.Unlock()
					return c.initCheckinObserved == initCheckinObserved
				}, waitDuration, 500*time.Millisecond, "timed out waiting for the c.initCheckinObserved to be set")

				// destroy the communicator and check that it exits without blocking
				c.destroy()
				select {
				case err := <-errCh:
					s, ok := status.FromError(err)
					assert.True(t, ok, "error must be a gRPC status")
					assert.Equal(t, codes.Unavailable, s.Code(), "status code must be unavailable")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}
			},
		},
		{
			name: "communicator destroyed before runtime sends init checkin observed",
			validateFlow: func(t *testing.T, c *runtimeComm, srv *testServer) {
				initCheckinObserved := &proto.CheckinObserved{}
				// checkin the communicator
				errCh := make(chan error, 1)
				go func() {
					errCh <- c.checkin(srv, initCheckinObserved)
				}()

				// wait for the communicator to send the init checkin observed
				select {
				case err := <-errCh:
					t.Fatalf("checkin shouldn't returned an error: %v", err)
				case observed := <-c.CheckinObserved():
					assert.Equal(t, initCheckinObserved, observed, "checkin observed message must match the init checkin observed message")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the init checkin observed")
				}

				// destroy the communicator and check that it exits without blocking
				c.destroy()
				select {
				case err := <-errCh:
					s, ok := status.FromError(err)
					assert.True(t, ok, "error must be a gRPC status")
					assert.Equal(t, codes.Unavailable, s.Code(), "status code must be unavailable")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}

				// simulate the runtime sending the checkin expected
				expected := &proto.CheckinExpected{}
				checkinDone := make(chan struct{})
				go func() {
					defer close(checkinDone)
					c.CheckinExpected(expected, initCheckinObserved)
				}()
				// check that the checkin doesn't block
				select {
				case <-checkinDone:
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}
				// check that we don't receive the checkin expected
				select {
				case <-srv.expected:
					t.Fatal("we should not have received the checkin expected message")
				case <-time.After(waitDuration):
				}
			},
		},
		{
			name: "server stopped before runtime sends init checkin observed",
			validateFlow: func(t *testing.T, c *runtimeComm, srv *testServer) {
				initCheckinObserved := &proto.CheckinObserved{}
				// checkin the communicator
				errCh := make(chan error, 1)
				go func() {
					errCh <- c.checkin(srv, initCheckinObserved)
				}()

				// wait for the communicator to send the init checkin observed
				select {
				case err := <-errCh:
					t.Fatalf("checkin shouldn't returned an error: %v", err)
				case observed := <-c.CheckinObserved():
					assert.Equal(t, initCheckinObserved, observed, "checkin observed message must match the init checkin observed message")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the init checkin observed")
				}

				// stop the server and wait for communicator checkin to exit
				srv.stop(nil)
				select {
				case err := <-errCh:
					s, ok := status.FromError(err)
					assert.True(t, ok, "error must be a gRPC status")
					assert.Equal(t, codes.Unavailable, s.Code(), "status code must be unavailable")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}

				// simulate the runtime sending the checkin expected with initCheckinObserved
				expected := &proto.CheckinExpected{}
				checkinDone := make(chan struct{})
				go func() {
					defer close(checkinDone)
					c.CheckinExpected(expected, initCheckinObserved)
				}()
				// check that the CheckinExpected doesn't block
				select {
				case <-checkinDone:
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}
				// check that we don't receive any expected message on the server
				select {
				case <-srv.expected:
					t.Fatal("we should not have received the checkin expected message")
				case <-time.After(waitDuration):
				}
			},
		},
		{
			name: "runtime wrong init checkin observed",
			validateFlow: func(t *testing.T, c *runtimeComm, srv *testServer) {
				initCheckinObserved := &proto.CheckinObserved{}
				// checkin the communicator
				errCh := make(chan error, 1)
				go func() {
					errCh <- c.checkin(srv, initCheckinObserved)
				}()

				// wait for the communicator to send the init checkin observed
				select {
				case err := <-errCh:
					t.Fatalf("checkin shouldn't returned an error: %v", err)
				case observed := <-c.CheckinObserved():
					assert.Equal(t, initCheckinObserved, observed, "checkin observed message must match the init checkin observed message")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the init checkin observed")
				}

				// simulate the runtime sending a checkin with a different init checkin observed
				expected := &proto.CheckinExpected{}
				differentInitCheckinObserved := &proto.CheckinObserved{}
				checkinDone := make(chan struct{})
				go func() {
					defer close(checkinDone)
					c.CheckinExpected(expected, differentInitCheckinObserved)
				}()
				// check that the checkin doesn't block
				select {
				case <-checkinDone:
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}
				// check that we don't receive the checkin expected
				select {
				case <-srv.expected:
					t.Fatal("expected to not receive the init checkin expected message")
				case <-time.After(waitDuration):
				}

				// simulate the runtime sending a checkin with the correct init checkin observed
				checkinDone = make(chan struct{})
				go func() {
					defer close(checkinDone)
					c.CheckinExpected(expected, initCheckinObserved)
				}()
				// check that the checkin doesn't block
				select {
				case <-checkinDone:
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}
				// check that we do receive the checkin expected
				select {
				case receivedExpected := <-srv.expected:
					assert.Equal(t, receivedExpected, expected, "expected to receive the checkin expected message")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin expected message")
				}
			},
		},
		{
			name: "against all odds send a second init checkin observed",
			validateFlow: func(t *testing.T, c *runtimeComm, srv *testServer) {
				initCheckinObserved := &proto.CheckinObserved{}
				// checkin the communicator
				errCh := make(chan error, 1)
				go func() {
					errCh <- c.checkin(srv, initCheckinObserved)
				}()

				// wait for the communicator to send the init checkin observed
				select {
				case err := <-errCh:
					t.Fatalf("checkin shouldn't returned an error: %v", err)
				case observed := <-c.CheckinObserved():
					assert.Equal(t, initCheckinObserved, observed, "checkin observed message must match the init checkin observed message")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the init checkin observed")
				}

				// simulate the runtime sending the checkin expected
				expected := &proto.CheckinExpected{}
				checkinDone := make(chan struct{})
				go func() {
					defer close(checkinDone)
					c.CheckinExpected(expected, initCheckinObserved)
				}()
				// check that the checkin doesn't block
				select {
				case <-checkinDone:
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}
				// check that we do receive the checkin expected
				select {
				case receivedExpected := <-srv.expected:
					assert.Equal(t, receivedExpected, expected, "expected to receive the checkin expected message")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting to receive the checkin expected message")
				}

				// force another init checkin observed to the initCheckinExpectedCh channel
				// and make sure that we ignore it
				select {
				case c.initCheckinExpectedCh <- expected:
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting to write the init checkin expected message")
				}
				// check that we don't receive the checkin expected
				select {
				case <-srv.expected:
					t.Fatal("we should not receive any expected message")
				case <-time.After(waitDuration):
				}
			},
		},
		{
			name: "after init checkin observed runtime checkins flow unblocked",
			validateFlow: func(t *testing.T, c *runtimeComm, srv *testServer) {
				initCheckinObserved := &proto.CheckinObserved{}
				// checkin the communicator
				errCh := make(chan error, 1)
				go func() {
					errCh <- c.checkin(srv, initCheckinObserved)
				}()

				// wait for the communicator to send the init checkin observed
				select {
				case err := <-errCh:
					t.Fatalf("checkin shouldn't returned an error: %v", err)
				case observed := <-c.CheckinObserved():
					assert.Equal(t, initCheckinObserved, observed, "checkin observed message must match the init checkin observed message")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the init checkin observed")
				}

				// simulate the runtime sending the checkin expected
				expected := &proto.CheckinExpected{}
				checkinDone := make(chan struct{})
				go func() {
					defer close(checkinDone)
					c.CheckinExpected(expected, initCheckinObserved)
				}()
				// check that the checkin doesn't block
				select {
				case <-checkinDone:
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}

				// bombard the runtime with checkin expected and make sure that we receive the last expected checkin
				lastExpectedSentCh := make(chan *proto.CheckinExpected)
				go func() {
					var lastExpected *proto.CheckinExpected
					const expectedCheckinCount = 10
					for i := 0; i < expectedCheckinCount; i++ {
						lastExpected = &proto.CheckinExpected{}
						c.CheckinExpected(lastExpected, nil)
					}
					lastExpectedSentCh <- lastExpected
				}()

				// wait for the goroutine above to exit and get the last checkin expected sent from the goroutine above
				// it shouldn't block
				var lastExpectedSent *proto.CheckinExpected
				select {
				case lastExpectedSent = <-lastExpectedSentCh:
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}

				// wait to get the last checkin expected as reported by the communicator to the server
				// which needs to match the above lastExpectedSent
				seenLastExpected := false
				for !seenLastExpected {
					select {
					case receivedExpected := <-srv.expected:
						if receivedExpected != lastExpectedSent {
							continue
						}
						assert.Equal(t, receivedExpected, lastExpectedSent, "expected to receive the last checkin expected message")
						seenLastExpected = true
					case <-time.After(waitDuration):
						t.Fatal("timed out waiting to receive the last checkin expected message")
					}
				}

				// make sure that we don't receive any more expected checkin messages
				select {
				case <-srv.expected:
					t.Fatal("we should not receive any expected message")
				case <-time.After(waitDuration):
				}
			},
		},
		{
			name: "communicator can be re-used at server reconnect",
			validateFlow: func(t *testing.T, c *runtimeComm, srv *testServer) {
				initCheckinObserved := &proto.CheckinObserved{}
				// checkin the communicator
				errCh := make(chan error, 1)
				go func() {
					errCh <- c.checkin(srv, initCheckinObserved)
				}()

				// wait for the communicator to send the init checkin observed
				select {
				case err := <-errCh:
					t.Fatalf("checkin shouldn't returned an error: %v", err)
				case observed := <-c.CheckinObserved():
					assert.Equal(t, initCheckinObserved, observed, "checkin observed message must match the init checkin observed message")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the init checkin observed")
				}

				// stop the server and wait for communicator checkin to exit
				srv.stop(nil)
				select {
				case err := <-errCh:
					s, ok := status.FromError(err)
					assert.True(t, ok, "error must be a gRPC status")
					assert.Equal(t, codes.Unavailable, s.Code(), "status code must be unavailable")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}

				// renew the context of the server and invoke again the communicator checkin
				srv.renewContext(t.Context())
				secondCheckinObserved := &proto.CheckinObserved{}
				errCh = make(chan error, 1)
				go func() {
					errCh <- c.checkin(srv, secondCheckinObserved)
				}()

				// wait for the communicator to send the init checkin observed
				select {
				case err := <-errCh:
					t.Fatalf("checkin shouldn't returned an error: %v", err)
				case observed := <-c.CheckinObserved():
					assert.Equal(t, secondCheckinObserved, observed, "checkin observed message must match the second init checkin observed message")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the init checkin observed")
				}

				// simulate the runtime sending the checkin expected with the first init checkin observed
				expected := &proto.CheckinExpected{}
				checkinDone := make(chan struct{})
				go func() {
					defer close(checkinDone)
					c.CheckinExpected(expected, initCheckinObserved)
				}()
				// check that the checkin doesn't block
				select {
				case <-checkinDone:
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}
				// check that we do not receive the checkin expected from the first init checkin observed
				select {
				case <-srv.expected:
					t.Fatal("we should not receive any expected message")
				case <-time.After(waitDuration):
				}

				// simulate the runtime sending the checkin expected with the correct and second init checkin observed
				checkinDone = make(chan struct{})
				go func() {
					defer close(checkinDone)
					c.CheckinExpected(expected, secondCheckinObserved)
				}()
				// check that the checkin doesn't block
				select {
				case <-checkinDone:
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting for the checkin to return")
				}
				// check that we do receive the checkin expected from the second init checkin observed
				select {
				case receivedExpected := <-srv.expected:
					assert.Equal(t, receivedExpected, expected, "expected to receive the checkin expected message")
				case <-time.After(waitDuration):
					t.Fatal("timed out waiting to receive the checkin expected message")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log, _ := loggertest.New("TestPolicyChangeHandler")
			c, err := newRuntimeComm(log, "localhost", ca, agentInfoMock{}, 0)
			require.NoError(t, err, "could not create runtime comm")

			srv := newTestServer(t.Context())
			tc.validateFlow(t, c, srv)
		})
	}
}

func newTestServer(ctx context.Context) *testServer {
	ctx, cancel := context.WithCancelCause(ctx)
	return &testServer{
		ctx:      ctx,
		cancel:   cancel,
		expected: make(chan *proto.CheckinExpected),
		observed: make(chan *proto.CheckinObserved),
	}
}

type testServer struct {
	ctx      context.Context
	cancel   context.CancelCauseFunc
	expected chan *proto.CheckinExpected
	observed chan *proto.CheckinObserved
}

func (t *testServer) renewContext(ctx context.Context) {
	t.ctx, t.cancel = context.WithCancelCause(ctx)
}

func (t *testServer) stop(err error) {
	t.cancel(err)
}
func (t *testServer) Send(expected *proto.CheckinExpected) error {
	select {
	case t.expected <- expected:
		return nil
	case <-t.ctx.Done():
		return context.Cause(t.ctx)
	}
}

func (t *testServer) Recv() (*proto.CheckinObserved, error) {
	select {
	case observed := <-t.observed:
		return observed, nil
	case <-t.ctx.Done():
		return nil, context.Cause(t.ctx)
	}
}

func (t *testServer) SetHeader(_ metadata.MD) error {
	// not needed for the current testing needs, thus panic if called
	panic("unimplemented")
}

func (t *testServer) SendHeader(_ metadata.MD) error {
	// not needed for the current testing needs, thus panic if called
	panic("unimplemented")
}

func (t *testServer) SetTrailer(_ metadata.MD) {
	// not needed for the current testing needs, thus panic if called
	panic("unimplemented")
}

func (t *testServer) Context() context.Context {
	return t.ctx
}

func (t *testServer) SendMsg(_ any) error {
	// not needed for the current testing needs, thus panic if called
	panic("unimplemented")
}

func (t *testServer) RecvMsg(_ any) error {
	// not needed for the current testing needs, thus panic if called
	panic("unimplemented")
}
