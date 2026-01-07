// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"

	eaclient "github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/scheduler"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	agentclient "github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

type clientCallbackFunc func(ctx context.Context, headers http.Header, body io.Reader) (*http.Response, error)

type testingClient struct {
	sync.Mutex
	callback clientCallbackFunc
	received chan struct{}
}

func (t *testingClient) Send(
	ctx context.Context,
	_ string,
	_ string,
	_ url.Values,
	headers http.Header,
	body io.Reader,
) (*http.Response, error) {
	t.Lock()
	defer t.Unlock()
	defer func() { t.received <- struct{}{} }()
	return t.callback(ctx, headers, body)
}

func (t *testingClient) URI() string {
	return "http://localhost"
}

func (t *testingClient) Answer(fn clientCallbackFunc) <-chan struct{} {
	t.Lock()
	defer t.Unlock()
	t.callback = fn
	return t.received
}

func newTestingClient() *testingClient {
	return &testingClient{received: make(chan struct{}, 1)}
}

type withGatewayFunc func(*testing.T, coordinator.FleetGateway, *testingClient, *scheduler.Stepper)

func withGateway(agentInfo agentInfo, settings *fleetGatewaySettings, fn withGatewayFunc) func(t *testing.T) {
	return func(t *testing.T) {
		scheduler := scheduler.NewStepper()
		client := newTestingClient()

		log, _ := logger.New("fleet_gateway", false)

		stateStore := newStateStore(t, log)

		mockRollbacksSrc := newMockRollbacksSource(t)
		mockRollbacksSrc.EXPECT().Get().Return(nil, nil)

		gateway, err := newFleetGatewayWithScheduler(log, settings, agentInfo, client, scheduler, noop.New(), stateStore, NewCheckinStateFetcher(emptyStateFetcher), mockRollbacksSrc)

		require.NoError(t, err)

		fn(t, gateway, client, scheduler)
	}
}

func ackSeq(channels ...<-chan struct{}) func() {
	return func() {
		for _, c := range channels {
			<-c
		}
	}
}

func wrapStrToResp(code int, body string) *http.Response {
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", code, http.StatusText(code)),
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewBufferString(body)),
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
	}
}

func TestFleetGateway(t *testing.T) {
	agentInfo := &testAgentInfo{}
	settings := &fleetGatewaySettings{
		Duration: 5 * time.Second,
		Backoff:  &backoffSettings{Init: 1 * time.Second, Max: 5 * time.Second},
	}

	t.Run("send no event and receive no action", withGateway(agentInfo, settings, func(
		t *testing.T,
		gateway coordinator.FleetGateway,
		client *testingClient,
		scheduler *scheduler.Stepper,
	) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		waitFn := ackSeq(
			client.Answer(func(_ context.Context, headers http.Header, body io.Reader) (*http.Response, error) {
				resp := wrapStrToResp(http.StatusOK, `{ "actions": [] }`)
				return resp, nil
			}),
		)

		errCh := runFleetGateway(ctx, gateway)

		// Synchronize scheduler and acking of calls from the worker go routine.
		scheduler.Next()
		waitFn()

		cancel()
		err := <-errCh
		require.NoError(t, err)
		select {
		case actions := <-gateway.Actions():
			t.Errorf("Expected no actions, got %v", actions)
		default:
		}
	}))

	t.Run("Successfully connects and receives a series of actions", withGateway(agentInfo, settings, func(
		t *testing.T,
		gateway coordinator.FleetGateway,
		client *testingClient,
		scheduler *scheduler.Stepper,
	) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		waitFn := ackSeq(
			client.Answer(func(_ context.Context, headers http.Header, body io.Reader) (*http.Response, error) {
				// TODO: assert no events
				resp := wrapStrToResp(http.StatusOK, `
	{
		"actions": [
			{
				"type": "POLICY_CHANGE",
				"id": "id1",
				"data": {
					"policy": {
						"id": "policy-id"
					}
				}
			},
			{
				"type": "ANOTHER_ACTION",
				"id": "id2"
			}
		]
	}
	`)
				return resp, nil
			}),
		)

		errCh := runFleetGateway(ctx, gateway)

		scheduler.Next()
		waitFn()

		cancel()
		err := <-errCh
		require.NoError(t, err)
		select {
		case actions := <-gateway.Actions():
			require.Len(t, actions, 2)
		default:
			t.Errorf("Expected to receive actions")
		}
	}))

	// Test the normal time based execution.
	t.Run("Periodically communicates with Fleet", func(t *testing.T) {
		scheduler := scheduler.NewPeriodic(150 * time.Millisecond)
		client := newTestingClient()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		log, _ := logger.New("tst", false)
		stateStore := newStateStore(t, log)

		mockRollbacksSrc := newMockRollbacksSource(t)
		mockRollbacksSrc.EXPECT().Get().Return(nil, nil)

		gateway, err := newFleetGatewayWithScheduler(log, settings, agentInfo, client, scheduler, noop.New(), stateStore, NewCheckinStateFetcher(emptyStateFetcher), mockRollbacksSrc)
		require.NoError(t, err)

		waitFn := ackSeq(
			client.Answer(func(_ context.Context, headers http.Header, body io.Reader) (*http.Response, error) {
				resp := wrapStrToResp(http.StatusOK, `{ "actions": [] }`)
				return resp, nil
			}),
		)

		errCh := runFleetGateway(ctx, gateway)

		func() {
			var count int
			for {
				waitFn()
				count++
				if count == 4 {
					return
				}
			}
		}()

		cancel()
		err = <-errCh
		require.NoError(t, err)
	})

	t.Run("Test the wait loop is interruptible", func(t *testing.T) {
		// 20mins is the double of the base timeout values for golang test suites.
		// If we cannot interrupt we will timeout.
		d := 20 * time.Minute
		scheduler := scheduler.NewPeriodic(d)
		client := newTestingClient()

		ctx, cancel := context.WithCancel(context.Background())

		log, _ := logger.New("tst", false)
		stateStore := newStateStore(t, log)

		mockRollbacksSrc := newMockRollbacksSource(t)
		mockRollbacksSrc.EXPECT().Get().Return(nil, nil)

		gateway, err := newFleetGatewayWithScheduler(log, &fleetGatewaySettings{
			Duration: d,
			Backoff:  &backoffSettings{Init: 1 * time.Second, Max: 30 * time.Second},
		}, agentInfo, client, scheduler, noop.New(), stateStore, NewCheckinStateFetcher(emptyStateFetcher), mockRollbacksSrc)
		require.NoError(t, err)

		ch2 := client.Answer(func(_ context.Context, headers http.Header, body io.Reader) (*http.Response, error) {
			resp := wrapStrToResp(http.StatusOK, `{ "actions": [] }`)
			return resp, nil
		})

		errCh := runFleetGateway(ctx, gateway)

		// Make sure that all API calls to the checkin API are successful, the following will happen:
		// block on the first call.
		<-ch2

		go func() {
			// drain the channel
			for range ch2 {
			}
		}()

		// 1. Gateway will check the API on boot.
		// 2. WaitTick() will block for 20 minutes.
		// 3. Stop will should unblock the wait.
		cancel()
		err = <-errCh
		require.NoError(t, err)
	})

	t.Run("Sends upgrade details", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		scheduler := scheduler.NewStepper()
		client := newTestingClient()

		log, _ := loggertest.New("fleet_gateway")

		stateStore := newStateStore(t, log)

		upgradeDetails := &details.Details{
			TargetVersion: "8.12.0",
			State:         "UPG_WATCHING",
			ActionID:      "foobarbaz",
		}
		stateFetcher := func() coordinator.State {
			return coordinator.State{
				UpgradeDetails: upgradeDetails,
			}
		}

		mockRollbacksSrc := newMockRollbacksSource(t)
		mockRollbacksSrc.EXPECT().Get().Return(nil, nil)

		gateway, err := newFleetGatewayWithScheduler(log, settings, agentInfo, client, scheduler, noop.New(), stateStore, NewCheckinStateFetcher(stateFetcher), mockRollbacksSrc)

		require.NoError(t, err)

		waitFn := ackSeq(
			client.Answer(func(_ context.Context, headers http.Header, body io.Reader) (*http.Response, error) {
				data, err := io.ReadAll(body)
				require.NoError(t, err)

				var checkinRequest fleetapi.CheckinRequest
				err = json.Unmarshal(data, &checkinRequest)
				require.NoError(t, err)

				require.NotNil(t, checkinRequest.UpgradeDetails)
				require.Equal(t, upgradeDetails, checkinRequest.UpgradeDetails)

				resp := wrapStrToResp(http.StatusOK, `{ "actions": [] }`)
				return resp, nil
			}),
		)

		errCh := runFleetGateway(ctx, gateway)

		// Synchronize scheduler and acking of calls from the worker go routine.
		scheduler.Next()
		waitFn()

		cancel()
		err = <-errCh
		require.NoError(t, err)
		select {
		case actions := <-gateway.Actions():
			t.Errorf("Expected no actions, got %v", actions)
		default:
		}
	})

	t.Run("sends agent_policy_id and policy_revision_idx", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		scheduler := scheduler.NewStepper()
		client := newTestingClient()

		log, _ := loggertest.New("fleet_gateway")

		stateStore := newStateStore(t, log)
		stateStore.SetAction(&fleetapi.ActionPolicyChange{
			ActionID:   "test-action-id",
			ActionType: fleetapi.ActionTypePolicyChange,
			Data: fleetapi.ActionPolicyChangeData{
				Policy: map[string]interface{}{
					"policy_id":           "test-policy-id",
					"policy_revision_idx": 1,
				},
			},
		})
		err := stateStore.Save()
		require.NoError(t, err)

		mockRollbacksSrc := newMockRollbacksSource(t)
		mockRollbacksSrc.EXPECT().Get().Return(nil, nil)

		gateway, err := newFleetGatewayWithScheduler(log, settings, agentInfo, client, scheduler, noop.New(), stateStore, NewCheckinStateFetcher(emptyStateFetcher), mockRollbacksSrc)
		require.NoError(t, err)

		waitFn := ackSeq(
			client.Answer(func(_ context.Context, headers http.Header, body io.Reader) (*http.Response, error) {
				data, err := io.ReadAll(body)
				require.NoError(t, err)

				var checkinRequest fleetapi.CheckinRequest
				err = json.Unmarshal(data, &checkinRequest)
				require.NoError(t, err)

				require.Equal(t, "test-policy-id", checkinRequest.AgentPolicyID)
				require.Equal(t, int64(1), checkinRequest.PolicyRevisionIDX)

				resp := wrapStrToResp(http.StatusOK, `{ "actions": [] }`)
				return resp, nil
			}),
		)

		errCh := runFleetGateway(ctx, gateway)

		// Synchronize scheduler and acking of calls from the worker go routine.
		scheduler.Next()
		waitFn()

		cancel()
		err = <-errCh
		require.NoError(t, err)
		select {
		case actions := <-gateway.Actions():
			t.Errorf("Expected no actions, got %v", actions)
		default:
		}
	})

	t.Run("Test cancel checkin on state update", func(t *testing.T) {
		scheduler := scheduler.NewStepper()
		client := newTestingClient()

		ctx, cancel := context.WithCancel(context.Background())

		log, _ := logger.New("tst", false)
		stateStore := newStateStore(t, log)

		stateChannel := make(chan coordinator.State, 10)

		stateFetcher := NewFastCheckinStateFetcher(log, emptyStateFetcher, stateChannel)

		mockRollbacksSrc := newMockRollbacksSource(t)
		mockRollbacksSrc.EXPECT().Get().Return(nil, nil)

		gateway, err := newFleetGatewayWithScheduler(log, &fleetGatewaySettings{
			Duration: 5 * time.Second,
			Backoff:  &backoffSettings{Init: 10 * time.Millisecond, Max: 30 * time.Second},
		}, agentInfo, client, scheduler, noop.New(), stateStore, stateFetcher, mockRollbacksSrc)
		require.NoError(t, err)

		requestSent := make(chan struct{}, 10)

		// (emulate long poll) wait for the context to be cancelled
		ch2 := client.Answer(func(ctx context.Context, headers http.Header, body io.Reader) (*http.Response, error) {
			requestSent <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		})

		wg := sync.WaitGroup{}

		// custom runFleetGateway
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := gateway.Run(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				assert.NoError(t, err)
			}
		}()

		// start state watcher
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := stateFetcher.StartStateWatch(ctx)
			assert.ErrorIs(t, err, context.Canceled)
		}()

		// trigger cmd loop
		scheduler.Next()
		// ensure that checkin request was sent (and it is waiting) and then interrupt with state change.
		<-requestSent
		// State change arrives while waiting on fleet sever long poll
		stateChannel <- coordinator.State{}

		// wait for fleet ctx canceled error
		<-ch2

		// ensure that this specific error returned from f.execute
		executeErr := <-gateway.errCh
		assert.ErrorIs(t, executeErr, errComponentStateChanged)

		cancel()
		wg.Wait()
	})
}

func TestRetriesOnFailures(t *testing.T) {
	agentInfo := &testAgentInfo{}
	settings := &fleetGatewaySettings{
		Duration: 5 * time.Second,
		Backoff:  &backoffSettings{Init: 100 * time.Millisecond, Max: 5 * time.Second},
	}

	t.Run("When the gateway fails to communicate with the checkin API we will retry",
		withGateway(agentInfo, settings, func(
			t *testing.T,
			gateway coordinator.FleetGateway,
			client *testingClient,
			scheduler *scheduler.Stepper,
		) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			fail := func(_ context.Context, _ http.Header, _ io.Reader) (*http.Response, error) {
				return wrapStrToResp(http.StatusInternalServerError, "something is bad"), nil
			}
			clientWaitFn := client.Answer(fail)

			errCh := runFleetGateway(ctx, gateway)

			// Initial tick is done out of bound so we can block on channels.
			scheduler.Next()

			// Simulate a 500 errors for the next 3 calls.
			<-clientWaitFn
			<-clientWaitFn
			<-clientWaitFn

			// API recover
			waitFn := ackSeq(
				client.Answer(func(_ context.Context, _ http.Header, body io.Reader) (*http.Response, error) {
					resp := wrapStrToResp(http.StatusOK, `{ "actions": [] }`)
					return resp, nil
				}),
			)

			waitFn()

			cancel()
			err := <-errCh
			require.NoError(t, err)
			select {
			case actions := <-gateway.Actions():
				t.Errorf("Expected no actions, got %v", actions)
			default:
			}
		}))

	t.Run("The retry loop is interruptible",
		withGateway(agentInfo, &fleetGatewaySettings{
			Duration: 0 * time.Second,
			Backoff:  &backoffSettings{Init: 10 * time.Minute, Max: 20 * time.Minute},
		}, func(
			t *testing.T,
			gateway coordinator.FleetGateway,
			client *testingClient,
			scheduler *scheduler.Stepper,
		) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			fail := func(_ context.Context, _ http.Header, _ io.Reader) (*http.Response, error) {
				return wrapStrToResp(http.StatusInternalServerError, "something is bad"), nil
			}
			waitChan := client.Answer(fail)

			errCh := runFleetGateway(ctx, gateway)

			// Initial tick is done out of bound so we can block on channels.
			scheduler.Next()

			// Fail to enter retry loop, all other calls will fails and will force to wait on big initial
			// delay.
			<-waitChan

			cancel()
			err := <-errCh
			require.NoError(t, err)
		}))
}

type testAgentInfo struct{}

func (testAgentInfo) AgentID() string { return "agent-secret" }

func emptyStateFetcher() coordinator.State {
	return coordinator.State{}
}

func runFleetGateway(ctx context.Context, g coordinator.FleetGateway) <-chan error {
	done := make(chan bool)
	errCh := make(chan error, 1)
	go func() {
		err := g.Run(ctx)
		close(done)
		if err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		} else {
			errCh <- nil
		}
	}()
	go func() {
		for {
			select {
			case <-done:
				return
			case <-g.Errors():
				// ignore errors here
			}
		}
	}()
	return errCh
}

func newStateStore(t *testing.T, log *logger.Logger) *store.StateStore {
	dir := t.TempDir()

	filename := filepath.Join(dir, "state.enc")
	diskStore, err := storage.NewDiskStore(filename)
	require.NoError(t, err)
	stateStore, err := store.NewStateStore(log, diskStore)
	require.NoError(t, err)

	return stateStore
}

func TestAgentStateToString(t *testing.T) {
	testcases := []struct {
		agentState         agentclient.State
		expectedFleetState string
	}{
		{
			agentState:         agentclient.Healthy,
			expectedFleetState: fleetStateOnline,
		},
		{
			agentState:         agentclient.Failed,
			expectedFleetState: fleetStateError,
		},
		{
			agentState:         agentclient.Starting,
			expectedFleetState: fleetStateStarting,
		},
		// everything else maps to degraded
		{
			agentState:         agentclient.Configuring,
			expectedFleetState: fleetStateOnline,
		},
		{
			agentState:         agentclient.Degraded,
			expectedFleetState: fleetStateDegraded,
		},
		{
			agentState:         agentclient.Stopping,
			expectedFleetState: fleetStateOnline,
		},
		{
			agentState:         agentclient.Stopped,
			expectedFleetState: fleetStateOnline,
		},
		{
			agentState:         agentclient.Upgrading,
			expectedFleetState: fleetStateOnline,
		},
		{
			agentState:         agentclient.Rollback,
			expectedFleetState: fleetStateDegraded,
		},
		{
			// Unknown states should map to degraded.
			agentState:         agentclient.Rollback + 1,
			expectedFleetState: fleetStateDegraded,
		},
	}

	for _, tc := range testcases {
		t.Run(fmt.Sprintf("%s -> %s", tc.agentState, tc.expectedFleetState), func(t *testing.T) {
			actualFleetState := agentStateToString(tc.agentState)
			assert.Equal(t, tc.expectedFleetState, actualFleetState)
		})
	}
}

type MockScheduler struct {
	Duration time.Duration
	Ticker   *time.Ticker
}

func (m *MockScheduler) WaitTick() <-chan time.Time {
	return m.Ticker.C
}

func (m *MockScheduler) SetDuration(d time.Duration) {
	m.Duration = d
}

func (m *MockScheduler) Stop() {
	m.Ticker.Stop()
}

func TestFleetGatewaySchedulerSwitch(t *testing.T) {
	agentInfo := &testAgentInfo{}
	settings := &fleetGatewaySettings{
		Duration: 1 * time.Second,
		Backoff:  &backoffSettings{Init: 1 * time.Millisecond, Max: 2 * time.Millisecond},
	}

	tempSet := *defaultGatewaySettings
	defaultGatewaySettings.Duration = 500 * time.Millisecond
	defaultGatewaySettings.ErrConsecutiveUnauthDuration = 700 * time.Millisecond
	defer func() {
		*defaultGatewaySettings = tempSet
	}()

	t.Run("if unauthorized responses exceed the set limit, the scheduler should be switched to the long-wait scheduler", withGateway(agentInfo, settings, func(
		t *testing.T,
		gateway coordinator.FleetGateway,
		c *testingClient,
		sch *scheduler.Stepper,
	) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		unauth := func(_ context.Context, _ http.Header, _ io.Reader) (*http.Response, error) {
			return nil, client.ErrInvalidAPIKey
		}

		clientWaitFn := c.Answer(unauth)
		g, ok := gateway.(*FleetGateway)
		require.True(t, ok)

		ms := &MockScheduler{
			Duration: defaultGatewaySettings.Duration,
			Ticker:   time.NewTicker(defaultGatewaySettings.Duration),
		}
		g.scheduler = ms
		errCh := runFleetGateway(ctx, gateway)

		for i := 0; i <= maxUnauthCounter; i++ {
			<-clientWaitFn
		}

		cancel()
		err := <-errCh
		require.NoError(t, err)

		require.Equal(t, ms.Duration, defaultGatewaySettings.ErrConsecutiveUnauthDuration)
	}))

	t.Run("should switch back to short-wait scheduler if the a successful response is received", withGateway(agentInfo, settings, func(
		t *testing.T,
		gateway coordinator.FleetGateway,
		c *testingClient,
		sch *scheduler.Stepper,
	) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		unauth := func(_ context.Context, _ http.Header, _ io.Reader) (*http.Response, error) {
			resp := wrapStrToResp(http.StatusOK, `{ "actions": [] }`)
			return resp, nil
		}

		clientWaitFn := c.Answer(unauth)
		g, ok := gateway.(*FleetGateway)
		require.True(t, ok)

		ms := &MockScheduler{
			Duration: defaultGatewaySettings.ErrConsecutiveUnauthDuration,
			Ticker:   time.NewTicker(defaultGatewaySettings.ErrConsecutiveUnauthDuration),
		}
		g.scheduler = ms
		errCh := runFleetGateway(ctx, gateway)

		<-clientWaitFn

		cancel()
		err := <-errCh
		require.NoError(t, err)

		require.Equal(t, ms.Duration, defaultGatewaySettings.Duration)
	}))
}

func TestFastCheckinStateFetcher(t *testing.T) {
	init := func(t *testing.T) *FastCheckinStateFetcher {
		log, _ := logger.New("state_fetcher_"+t.Name(), false)
		ch := make(chan coordinator.State, 10)
		s := NewFastCheckinStateFetcher(log, emptyStateFetcher, ch)

		wg := sync.WaitGroup{}
		wg.Add(1)

		ctx, cnl := context.WithCancel(t.Context())
		go func() {
			defer wg.Done()
			err := s.StartStateWatch(ctx)
			assert.ErrorIs(t, err, context.Canceled, "error on StartStateWatch")
		}()

		t.Cleanup(func() {
			cnl()
			wg.Wait()
		})

		return s
	}

	t.Run("calling done with empty state should be noop", func(t *testing.T) {
		s := init(t)
		assert.Nil(t, s.cancel)
		s.Done()
		assert.Nil(t, s.cancel)
	})

	t.Run("fetch state and then done", func(t *testing.T) {
		s := init(t)
		assert.Nil(t, s.cancel)

		_, ctx := s.FetchState(t.Context())
		assert.NoError(t, ctx.Err())
		assert.NotNil(t, s.cancel)

		s.Done()
		assert.Nil(t, s.cancel)
		assert.NotErrorIs(t, context.Cause(ctx), errComponentStateChanged)
		assert.ErrorIs(t, ctx.Err(), context.Canceled)
	})

	t.Run("state change should invalidate context", func(t *testing.T) {
		s := init(t)
		assert.Nil(t, s.cancel)

		_, ctx := s.FetchState(t.Context())
		assert.NoError(t, ctx.Err())
		assert.NotNil(t, s.cancel)

		s.stateChan <- coordinator.State{}

		<-ctx.Done()
		assert.ErrorIs(t, context.Cause(ctx), errComponentStateChanged)
		assert.ErrorIs(t, ctx.Err(), context.Canceled)

		s.mutex.Lock()
		assert.Nil(t, s.cancel)
		s.mutex.Unlock()
	})
}

func TestConvertToCheckingComponents(t *testing.T) {
	tests := []struct {
		name       string
		components []runtime.ComponentComponentState
		collector  *status.AggregateStatus
		expected   []fleetapi.CheckinComponent
	}{
		{
			name:       "Nil inputs",
			components: nil,
			collector:  nil,
			expected:   nil,
		},
		{
			name:       "Empty inputs",
			components: []runtime.ComponentComponentState{},
			collector:  &status.AggregateStatus{},
			expected:   []fleetapi.CheckinComponent{},
		},
		{
			name: "Only agent components",
			components: []runtime.ComponentComponentState{
				{
					Component: component.Component{ID: "comp-1", InputSpec: &component.InputRuntimeSpec{InputType: "log"}},
					State: runtime.ComponentState{
						State:   eaclient.UnitStateHealthy,
						Message: "Component is healthy",
					},
				},
				{
					Component: component.Component{ID: "comp-2", InputSpec: &component.InputRuntimeSpec{InputType: "log"}},
					State: runtime.ComponentState{
						State:   eaclient.UnitStateDegraded,
						Message: "Component is degraded",
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
							{UnitID: "unit-1", UnitType: eaclient.UnitTypeInput}: {
								State:   eaclient.UnitStateFailed,
								Message: "Input unit failed",
								Payload: map[string]interface{}{"error": "some error"},
							},
						},
					},
				},
			},
			collector: nil,
			expected: []fleetapi.CheckinComponent{
				{
					ID:      "comp-1",
					Type:    "log",
					Status:  "HEALTHY",
					Message: "Component is healthy",
				},
				{
					ID:      "comp-2",
					Type:    "log",
					Status:  "DEGRADED",
					Message: "Component is degraded",
					Units: []fleetapi.CheckinUnit{
						{
							ID:      "unit-1",
							Type:    "input",
							Status:  "FAILED",
							Message: "Input unit failed",
							Payload: map[string]interface{}{"error": "some error"},
						},
					},
				},
			},
		},
		{
			name:       "Only OTel components",
			components: nil,
			collector: &status.AggregateStatus{
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"extensions": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
						ComponentStatusMap: map[string]*status.AggregateStatus{
							"extensions:healthcheck": {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
						},
					},
					"pipeline:logs": {
						Event: componentstatus.NewRecoverableErrorEvent(fmt.Errorf("pipeline error")),
						ComponentStatusMap: map[string]*status.AggregateStatus{
							"receiver:filebeat": {
								Event: componentstatus.NewEvent(componentstatus.StatusStarting),
							},
							"exporter:elasticsearch": {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
							"processor:batch": {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
						},
					},
				},
			},
			expected: []fleetapi.CheckinComponent{
				{
					ID:      "extensions",
					Type:    "otel",
					Status:  "HEALTHY",
					Message: "Healthy",
					Units: []fleetapi.CheckinUnit{
						{
							ID:      "extensions:healthcheck",
							Type:    "",
							Status:  "HEALTHY",
							Message: "Healthy",
						},
					},
				},
				{
					ID:      "pipeline:logs",
					Type:    "otel",
					Status:  "DEGRADED",
					Message: "Recoverable: pipeline error",
					Units: []fleetapi.CheckinUnit{
						{
							ID:      "exporter:elasticsearch",
							Type:    "output",
							Status:  "HEALTHY",
							Message: "Healthy",
						},
						{
							ID:      "processor:batch",
							Type:    "",
							Status:  "HEALTHY",
							Message: "Healthy",
						},
						{
							ID:      "receiver:filebeat",
							Type:    "input",
							Status:  "STARTING",
							Message: "Starting",
						},
					},
				},
			},
		},
		{
			name: "Both agent and OTel components",
			components: []runtime.ComponentComponentState{
				{
					Component: component.Component{ID: "comp-1", InputSpec: &component.InputRuntimeSpec{InputType: "log"}},
					State: runtime.ComponentState{
						State:   eaclient.UnitStateHealthy,
						Message: "Component is healthy",
					},
				},
			},
			collector: &status.AggregateStatus{
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"pipeline:logs": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
				},
			},
			expected: []fleetapi.CheckinComponent{
				{
					ID:      "comp-1",
					Type:    "log",
					Status:  "HEALTHY",
					Message: "Component is healthy",
				},
				{
					ID:      "pipeline:logs",
					Type:    "otel",
					Status:  "HEALTHY",
					Message: "Healthy",
				},
			},
		},
		{
			name: "Unknown states and types",
			components: []runtime.ComponentComponentState{
				{
					Component: component.Component{ID: "comp-1", InputSpec: &component.InputRuntimeSpec{InputType: "log"}},
					State: runtime.ComponentState{
						State:   eaclient.UnitState(99),
						Message: "Unknown state",
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
							{UnitID: "unit-1", UnitType: eaclient.UnitType(99)}: {
								State:   eaclient.UnitState(99),
								Message: "Unknown unit state",
							},
						},
					},
				},
			},
			collector: nil,
			expected: []fleetapi.CheckinComponent{
				{
					ID:      "comp-1",
					Type:    "log",
					Status:  "",
					Message: "Unknown state",
					Units: []fleetapi.CheckinUnit{
						{
							ID:      "unit-1",
							Type:    "",
							Status:  "",
							Message: "Unknown unit state",
						},
					},
				},
			},
		},
		{
			name:       "OTel component with invalid ID",
			components: []runtime.ComponentComponentState{},
			collector: &status.AggregateStatus{
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"invalid-id": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
						ComponentStatusMap: map[string]*status.AggregateStatus{
							"invalid-unit-id": {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
						},
					},
				},
			},
			expected: []fleetapi.CheckinComponent{
				{
					ID:      "invalid-id",
					Type:    "otel",
					Status:  "HEALTHY",
					Message: "Healthy",
					Units: []fleetapi.CheckinUnit{
						{
							ID:      "invalid-unit-id",
							Type:    "",
							Status:  "HEALTHY",
							Message: "Healthy",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertToCheckinComponents(logp.NewNopLogger(), tt.components, tt.collector)
			// Testify diffs are nicer if we sort and compare directly vs using ElementsMathc
			slices.SortFunc(result, func(a, b fleetapi.CheckinComponent) int {
				return strings.Compare(a.ID, b.ID)
			})
			for _, c := range result {
				slices.SortFunc(c.Units, func(a, b fleetapi.CheckinUnit) int {
					return strings.Compare(a.ID, b.ID)
				})
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAvailableRollbacks(t *testing.T) {
	testcases := []struct {
		name                  string
		setup                 func(t *testing.T, rbSource *mockRollbacksSource, client *testingClient)
		wantErr               assert.ErrorAssertionFunc
		assertCheckinResponse func(t *testing.T, resp *fleetapi.CheckinResponse)
	}{
		{
			name: "no available rollbacks - normal checkin",
			setup: func(t *testing.T, rbSource *mockRollbacksSource, client *testingClient) {
				rbSource.EXPECT().Get().Return(nil, nil)
				client.Answer(func(_ context.Context, _ http.Header, body io.Reader) (*http.Response, error) {
					unmarshaled := map[string]interface{}{}
					err := json.NewDecoder(body).Decode(&unmarshaled)
					assert.NoError(t, err, "error decoding checkin body")
					assert.NotContains(t, unmarshaled, "available_rollbacks")
					return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader("{}")),
						},
						nil
				})
			},
			wantErr:               assert.NoError,
			assertCheckinResponse: nil,
		},
		{
			name: "valid available rollbacks - assert key and value",
			setup: func(t *testing.T, rbSource *mockRollbacksSource, client *testingClient) {

				validUntil := time.Now().UTC().Add(time.Minute)
				// truncate to the second to avoid different precision due to marshal/unmarshal
				validUntil = validUntil.Truncate(time.Second)

				rbSource.EXPECT().Get().Return(map[string]ttl.TTLMarker{
					"data/elastic-agent-1.2.3-abcdef": {
						Version:    "1.2.3",
						Hash:       "abcdef",
						ValidUntil: validUntil,
					},
				}, nil)
				client.Answer(func(_ context.Context, _ http.Header, body io.Reader) (*http.Response, error) {
					unmarshaled := map[string]json.RawMessage{}
					err := json.NewDecoder(body).Decode(&unmarshaled)
					assert.NoError(t, err, "error decoding checkin body")
					if assert.Contains(t, unmarshaled, "upgrade") {
						// verify that we got the correct data
						var actualUpgrade fleetapi.CheckinUpgrade
						err = json.Unmarshal(unmarshaled["upgrade"], &actualUpgrade)
						require.NoError(t, err, "error decoding upgrade info from checkin body")

						expected := []fleetapi.CheckinRollback{{
							Version:    "1.2.3",
							ValidUntil: validUntil,
						}}
						assert.Equal(t, expected, actualUpgrade.Rollbacks)
					}

					return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader("{}")),
						},
						nil
				})
			},
			wantErr:               assert.NoError,
			assertCheckinResponse: nil,
		},
		{
			name: "Error getting rollbacks should not make the checkin error out, just omit available_rollbacks",
			setup: func(t *testing.T, rbSource *mockRollbacksSource, client *testingClient) {
				rbSource.EXPECT().Get().Return(nil, errors.New("some error getting rollbacks"))
				client.Answer(func(_ context.Context, _ http.Header, body io.Reader) (*http.Response, error) {
					unmarshaled := map[string]interface{}{}
					err := json.NewDecoder(body).Decode(&unmarshaled)
					assert.NoError(t, err, "error decoding checkin body")
					assert.NotContains(t, unmarshaled, "available_rollbacks")

					return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader("{}")),
						},
						nil
				})
			},
			wantErr:               assert.NoError,
			assertCheckinResponse: nil,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			stepperScheduler := scheduler.NewStepper()
			testClient := newTestingClient()
			log, _ := logger.New("fleet_gateway", false)

			stateStore := newStateStore(t, log)

			mockRollbacksSrc := newMockRollbacksSource(t)

			mockAgentInfo := new(testAgentInfo)

			tc.setup(t, mockRollbacksSrc, testClient)

			gateway, err := newFleetGatewayWithScheduler(log, defaultGatewaySettings, mockAgentInfo, testClient, stepperScheduler, noop.New(), stateStore, NewCheckinStateFetcher(emptyStateFetcher), mockRollbacksSrc)
			require.NoError(t, err, "error creating gateway")
			checkinResponse, _, err := gateway.execute(t.Context())
			tc.wantErr(t, err)
			if tc.assertCheckinResponse != nil {
				tc.assertCheckinResponse(t, checkinResponse)
			}
		})
	}
}
