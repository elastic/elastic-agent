// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions/handlers"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop"
	"github.com/elastic/elastic-agent/internal/pkg/queue"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

type mockHandler struct {
	mock.Mock
}

func (h *mockHandler) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	args := h.Called(ctx, a, acker)
	return args.Error(0)
}

// need various action structs as the dispather uses type reflection for routing, not action.Type()
type mockAction struct {
	mock.Mock
}
type mockOtherAction struct {
	mockAction
}
type mockScheduledAction struct {
	mockAction
}
type mockRetryableAction struct {
	mockScheduledAction
}

func (m *mockAction) ID() string {
	args := m.Called()
	return args.String(0)
}
func (m *mockAction) Type() string {
	args := m.Called()
	return args.String(0)
}
func (m *mockAction) String() string {
	args := m.Called()
	return args.String(0)
}
func (m *mockAction) AckEvent() fleetapi.AckEvent {
	args := m.Called()
	return args.Get(0).(fleetapi.AckEvent)
}
func (m *mockScheduledAction) StartTime() (time.Time, error) {
	args := m.Called()
	return args.Get(0).(time.Time), args.Error(1)
}
func (m *mockScheduledAction) Expiration() (time.Time, error) {
	args := m.Called()
	return args.Get(0).(time.Time), args.Error(1)
}
func (m *mockRetryableAction) RetryAttempt() int {
	args := m.Called()
	return args.Int(0)
}
func (m *mockRetryableAction) SetRetryAttempt(n int) {
	m.Called(n)
}
func (m *mockRetryableAction) SetStartTime(ts time.Time) {
	m.Called(ts)
}
func (m *mockRetryableAction) GetError() error {
	args := m.Called()
	return args.Error(0)
}
func (m *mockRetryableAction) SetError(err error) {
	m.Called(err)
}

type mockSaver struct {
	mock.Mock
}

func (m *mockSaver) SetQueue(a []fleetapi.ScheduledAction) {
	m.Called(a)
}
func (m *mockSaver) Save() error {
	args := m.Called()
	return args.Error(0)
}

func TestActionDispatcher(t *testing.T) {
	detailsSetter := func(upgradeDetails *details.Details) {}
	ack := noop.New()
	log, _ := loggertest.New("TestActionDispatcher")
	t.Run("Success to dispatch multiples events", func(t *testing.T) {
		ctx := context.Background()
		def := &mockHandler{}
		saver := &mockSaver{}
		saver.On("Save").Return(nil).Once()
		saver.On("SetQueue", mock.Anything).Once()

		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		success1 := &mockHandler{}
		success2 := &mockHandler{}

		err = d.Register(&mockAction{}, success1)
		require.NoError(t, err)
		err = d.Register(&mockOtherAction{}, success2)
		require.NoError(t, err)

		action1 := &mockAction{}
		action1.On("Type").Return("action")
		action1.On("ID").Return("id")
		action2 := &mockOtherAction{}
		action2.On("Type").Return("action")
		action2.On("ID").Return("id")

		// TODO better matching for actions
		success1.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		success2.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		dispatchCtx, cancelFn := context.WithCancel(ctx)
		defer cancelFn()
		go d.Dispatch(dispatchCtx, detailsSetter, ack, action1, action2)
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		success1.AssertExpectations(t)
		success2.AssertExpectations(t)
		def.AssertNotCalled(t, "Handle", mock.Anything, mock.Anything, mock.Anything)
		saver.AssertExpectations(t)
	})

	t.Run("Unknown action are caught by the unknown handler", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		ctx := context.Background()

		saver := &mockSaver{}
		saver.On("Save").Return(nil).Once()
		saver.On("SetQueue", mock.Anything).Once()

		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)
		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		action := &mockOtherAction{}
		action.On("Type").Return("action")
		action.On("ID").Return("id")

		dispatchCtx, cancelFn := context.WithCancel(ctx)
		defer cancelFn()
		go d.Dispatch(dispatchCtx, detailsSetter, ack, action)
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		def.AssertExpectations(t)
		saver.AssertExpectations(t)
	})

	t.Run("Could not register two handlers on the same action", func(t *testing.T) {
		success1 := &mockHandler{}
		success2 := &mockHandler{}

		def := &mockHandler{}

		saver := &mockSaver{}

		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		err = d.Register(&mockAction{}, success1)
		require.NoError(t, err)

		err = d.Register(&mockAction{}, success2)
		require.Error(t, err)
		saver.AssertExpectations(t)
	})

	t.Run("Dispatched action is queued", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		saver := &mockSaver{}
		saver.On("Save").Return(nil).Once()
		saver.On("SetQueue", mock.Anything).Once()

		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)
		err = d.Register(&mockAction{}, def)
		require.NoError(t, err)

		action1 := &mockAction{}
		action1.On("Type").Return("action")
		action1.On("ID").Return("id")
		action2 := &mockScheduledAction{}
		action2.On("StartTime").Return(time.Now().Add(time.Hour), nil)
		action2.On("Type").Return("action")
		action2.On("ID").Return("id")

		dispatchCtx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		go d.Dispatch(dispatchCtx, detailsSetter, ack, action1, action2)
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		def.AssertExpectations(t)
		saver.AssertExpectations(t)
	})

	t.Run("Cancel queued upgrade action", func(t *testing.T) {
		saver := &mockSaver{}
		saver.On("Save").Return(nil).Once()
		saver.On("SetQueue", mock.Anything).Once()

		upgradeAction := &fleetapi.ActionUpgrade{
			ActionID:         "upgrade-action-id",
			ActionType:       fleetapi.ActionTypeUpgrade,
			ActionStartTime:  time.Now().Add(2 * time.Minute).Format(time.RFC3339),
			ActionExpiration: time.Now().Add(3 * time.Minute).Format(time.RFC3339),
			Data: fleetapi.ActionUpgradeData{
				Version: "9.3.0",
			},
		}

		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{upgradeAction}, saver)
		require.NoError(t, err)

		action := &fleetapi.ActionCancel{
			ActionType: fleetapi.ActionTypeCancel,
			ActionID:   "id",
			Data: fleetapi.ActionCancelData{
				TargetID: "upgrade-action-id",
			},
		}

		dispatchCtx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()

		def := &mockHandler{}

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		err = d.Register(&fleetapi.ActionCancel{}, handlers.NewCancel(log, actionQueue))
		require.NoError(t, err, "error registering cancel handler")

		dispatchCompleted := make(chan struct{})
		go func() {
			d.Dispatch(dispatchCtx, detailsSetter, ack, action)
			dispatchCompleted <- struct{}{}
		}()

		select {
		case err := <-d.Errors():
			t.Fatalf("Unexpected error: %v", err)
		case <-dispatchCompleted:
			// OK, expected to complete the dispatch without blocking on the errors channel
		}

		def.AssertExpectations(t)
		saver.AssertExpectations(t)
	})

	t.Run("Retrieve actions from queue", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Twice()

		action1 := &mockScheduledAction{}
		action1.On("StartTime").Return(time.Time{}, fleetapi.ErrNoStartTime)
		action1.On("Expiration").Return(time.Now().Add(time.Hour), fleetapi.ErrNoExpiration)
		action1.On("Type").Return(fleetapi.ActionTypeCancel)
		action1.On("ID").Return("id")

		saver := &mockSaver{}
		saver.On("Save").Return(nil).Once()
		saver.On("SetQueue", mock.Anything).Once()
		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)
		actionQueue.Add(action1, time.Now().UTC().Add(-time.Hour).Unix())

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)
		err = d.Register(&fleetapi.ActionCancel{}, def)
		require.NoError(t, err)

		action2 := &fleetapi.ActionCancel{
			ActionID:   "id",
			ActionType: fleetapi.ActionTypeCancel,
		}
		dispatchCtx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		go d.Dispatch(dispatchCtx, detailsSetter, ack, action2)
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		def.AssertExpectations(t)
		saver.AssertExpectations(t)
	})

	t.Run("Retrieve no actions from queue", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		saver := &mockSaver{}
		saver.On("Save").Return(nil).Once()
		saver.On("SetQueue", mock.Anything).Once()
		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)
		err = d.Register(&mockAction{}, def)
		require.NoError(t, err)

		dispatchCtx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()

		dispatchCompleted := make(chan struct{})
		go func() {
			d.Dispatch(dispatchCtx, detailsSetter, ack)
			close(dispatchCompleted)
		}()
		select {
		case err := <-d.Errors():
			t.Fatalf("Unexpected error: %v", err)
		case <-dispatchCompleted:
		}
		def.AssertNotCalled(t, "Handle", mock.Anything, mock.Anything, mock.Anything)
		saver.AssertExpectations(t)
	})

	t.Run("Dispatch of a retryable action returns an error", func(t *testing.T) {
		testError := errors.New("test error")
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(testError).Once()

		saver := &mockSaver{}
		saver.On("Save").Return(nil).Times(2)
		saver.On("SetQueue", mock.Anything).Times(2)
		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)
		err = d.Register(&mockRetryableAction{}, def)
		require.NoError(t, err)

		action := &mockRetryableAction{}
		action.On("Type").Return("action")
		action.On("ID").Return("id")
		action.On("StartTime").Return(time.Time{}, fleetapi.ErrNoStartTime).Once()
		action.On("SetError", mock.Anything).Once()
		action.On("RetryAttempt").Return(0).Once()
		action.On("SetRetryAttempt", 1).Once()
		action.On("SetStartTime", mock.Anything).Once()
		action.On("GetError").Return(testError).Once()

		dispatchCtx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		go d.Dispatch(dispatchCtx, detailsSetter, ack, action)
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		def.AssertExpectations(t)
		action.AssertExpectations(t)
		saver.AssertExpectations(t)
	})

	t.Run("Dispatch multiple events returns one error", func(t *testing.T) {
		saver := &mockSaver{}
		saver.On("Save").Return(nil).Once()
		saver.On("SetQueue", mock.Anything).Once()
		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)

		action1 := &mockAction{}
		action1.On("Type").Return("action")
		action1.On("ID").Return("id")

		action2 := &mockAction{}
		action2.On("Type").Return("action")
		action2.On("ID").Return("id")

		dispatchCtx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()

		def := &mockHandler{}
		def.On("Handle", dispatchCtx, action1, ack).Return(errors.New("first error")).Once()
		def.On("Handle", dispatchCtx, action2, ack).Return(errors.New("second error")).Once()

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		dispatchCompleted := make(chan struct{})
		go func() {
			d.Dispatch(dispatchCtx, detailsSetter, ack, action1, action2)
			dispatchCompleted <- struct{}{}
		}()

		// First, assert that the Dispatch method puts one error - the second one - on the error channel.
		select {
		case err := <-d.Errors():
			assert.EqualError(t, err, "second error")
		case <-dispatchCompleted:
			t.Fatal("Expected error")
		}

		// Second, assert that the Dispatch method completes without putting anything else on the error channel.
		select {
		case <-d.Errors():
			t.Fatal(err)
		case <-dispatchCompleted:
			// Expecting the dispatch to complete.
		}

		def.AssertExpectations(t)
	})

	t.Run("Dispatch multiples events in separate batch returns one error second one resets it", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("test error")).Once()
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		saver := &mockSaver{}
		saver.On("Save").Return(nil).Times(2)
		saver.On("SetQueue", mock.Anything).Times(2)
		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)
		err = d.Register(&mockAction{}, def)
		require.NoError(t, err)

		action1 := &mockAction{}
		action1.On("Type").Return("action")
		action1.On("ID").Return("id")
		action2 := &mockAction{}
		action2.On("Type").Return("action")
		action2.On("ID").Return("id")

		// Kind of a dirty work around to test an error return.
		// launch in another routing and sleep to check if an error is generated
		dispatchCtx1, cancelFn1 := context.WithCancel(context.Background())
		defer cancelFn1()
		go d.Dispatch(dispatchCtx1, detailsSetter, ack, action1)
		select {
		case err := <-d.Errors():
			if err == nil {
				t.Fatal("Expecting error")
			}
		case <-time.After(300 * time.Millisecond):
		}

		dispatchCtx2, cancelFn2 := context.WithCancel(context.Background())
		defer cancelFn2()
		go d.Dispatch(dispatchCtx2, detailsSetter, ack, action2)
		select {
		case err := <-d.Errors():
			if err != nil {
				t.Fatal("Unexpected error")
			}
		case <-time.After(300 * time.Millisecond):
		}

		def.AssertExpectations(t)
	})

	t.Run("report next scheduled upgrade", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle",
			mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Twice()
		action := &fleetapi.ActionUpgrade{
			ActionID:         "id",
			ActionType:       fleetapi.ActionTypeUpgrade,
			ActionStartTime:  time.Now().Add(2 * time.Minute).Format(time.RFC3339),
			ActionExpiration: time.Now().Add(3 * time.Minute).Format(time.RFC3339),
			Data: fleetapi.ActionUpgradeData{
				Version: "9.3.0",
			},
		}

		saver := &mockSaver{}
		saver.On("Save").Return(nil).Once()
		saver.On("SetQueue", mock.Anything).Once()
		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		var gotDetails *details.Details
		detailsSetter := func(upgradeDetails *details.Details) {
			gotDetails = upgradeDetails
		}

		d.Dispatch(context.Background(), detailsSetter, ack, action)
		select {
		case err := <-d.Errors():
			if err != nil {
				t.Errorf("Unexpected error from Dispatch: %v", err)
			}
		default:
		}

		require.NotNilf(t, gotDetails, "upgrade details should have been set")
		assert.Equal(t, gotDetails.State, details.StateScheduled)
		assert.NotZerof(t, gotDetails.Metadata.ScheduledAt, "upgrade details metadata must have the ScheduledAt set")
	})

	t.Run("report next scheduled upgrade if there is a valid and an expired upgrade action", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle",
			mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Twice()

		expiredAction := &fleetapi.ActionUpgrade{
			ActionID:         "id-expired",
			ActionType:       fleetapi.ActionTypeUpgrade,
			ActionStartTime:  time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
			ActionExpiration: time.Now().Add(-3 * time.Minute).Format(time.RFC3339),
		}

		saver := &mockSaver{}
		saver.On("Save").Return(nil).Once()
		saver.On("SetQueue", mock.Anything).Once()
		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{expiredAction}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		var gotDetails *details.Details
		detailsSetter := func(upgradeDetails *details.Details) {
			gotDetails = upgradeDetails
		}

		action := &fleetapi.ActionUpgrade{
			ActionID:         "id",
			ActionType:       fleetapi.ActionTypeUpgrade,
			ActionStartTime:  time.Now().Add(2 * time.Minute).Format(time.RFC3339),
			ActionExpiration: time.Now().Add(3 * time.Minute).Format(time.RFC3339),
		}

		d.Dispatch(context.Background(), detailsSetter, ack, action)
		select {
		case err := <-d.Errors():
			if err != nil {
				t.Errorf("Unexpected error from Dispatch: %v", err)
			}
		default:
		}

		require.NotNilf(t, gotDetails, "upgrade details should have been set")
		assert.Equal(t, gotDetails.State, details.StateScheduled)
		assert.Equal(t, gotDetails.ActionID, "id")
	})

	t.Run("do not report upgrade details if there is no new upgrade action", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle",
			mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Twice()

		saver := &mockSaver{}
		saver.On("Save").Return(nil).Once()
		saver.On("SetQueue", mock.Anything).Once()

		actionStartTime := time.Now().UTC().Add(2 * time.Minute).Truncate(time.Second)
		actionExpiration := time.Now().UTC().Add(3 * time.Minute).Truncate(time.Second)

		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{
			&fleetapi.ActionUpgrade{
				ActionID:         "my action ID",
				ActionType:       fleetapi.ActionTypeUpgrade,
				ActionStartTime:  actionStartTime.Format(time.RFC3339),
				ActionExpiration: actionExpiration.Format(time.RFC3339),
			},
		}, saver)
		require.NoError(t, err)

		var gotDetails *details.Details
		detailsSetter := func(upgradeDetails *details.Details) {
			gotDetails = upgradeDetails
		}

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		d.Dispatch(context.Background(), detailsSetter, ack)
		select {
		case err := <-d.Errors():
			if err != nil {
				t.Errorf("Unexpected error from Dispatch: %v", err)
			}
		default:
		}

		assert.Nil(t, gotDetails, "upgrade details should match")
	})

	t.Run("set upgrade to failed if the action expires", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle",
			mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Twice()
		expired := &fleetapi.ActionUpgrade{
			ActionID:         "id-expired",
			ActionType:       fleetapi.ActionTypeUpgrade,
			ActionStartTime:  time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
			ActionExpiration: time.Now().Add(-3 * time.Minute).Format(time.RFC3339),
		}

		saver := &mockSaver{}
		saver.On("Save").Return(nil).Twice()
		saver.On("SetQueue", mock.Anything).Twice()
		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{expired}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		var gotDetails *details.Details
		detailsSetter := func(upgradeDetails *details.Details) {
			gotDetails = upgradeDetails
		}

		d.Dispatch(context.Background(), detailsSetter, ack)
		select {
		case err := <-d.Errors():
			if err != nil {
				t.Errorf("Unexpected error from Dispatch: %v", err)
			}
		default:
		}

		require.NotNilf(t, gotDetails, "upgrade details cannot be nil")
		assert.Equal(t, details.StateFailed, gotDetails.State)
		assert.NotEmptyf(t, gotDetails.Metadata.ErrorMsg, "want an error message, got none")
		assert.Equalf(t, expired.ActionID, gotDetails.ActionID, "action id must be the same")

		// re-run dispatch and make sure that upgrade details do not clear (expired upgrade details should persist)
		var shouldNotSetDetails error
		detailsSetter = func(upgradeDetails *details.Details) {
			shouldNotSetDetails = errors.New("detailsSetter called")
		}

		// at the next dispatch expired upgrade details should go away
		d.Dispatch(context.Background(), detailsSetter, ack)
		select {
		case err := <-d.Errors():
			if err != nil {
				t.Errorf("Unexpected error from Dispatch: %v", err)
			}
		default:
		}
		require.NoError(t, shouldNotSetDetails, "set upgrade details should not be called")
	})

	t.Run("check that failed upgrade actions do not block newer ones from dispatching", func(t *testing.T) {
		// we start by dispatching a scheduled upgrade action
		ctx := t.Context()
		handlerErr := errors.New("text handler error")

		def := &mockHandler{}
		def.On("Handle",
			mock.Anything, mock.Anything, mock.Anything).
			Return(handlerErr).Once()

		saver := &mockSaver{}
		saver.On("Save").Return(nil).Times(4)
		saver.On("SetQueue", mock.Anything).Times(4)
		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		err = d.Register(&fleetapi.ActionUpgrade{}, def)
		require.NoError(t, err)

		var gotDetails *details.Details
		detailsSetter := func(upgradeDetails *details.Details) {
			gotDetails = upgradeDetails
		}

		initialScheduledUpgradeAction := &fleetapi.ActionUpgrade{
			ActionID:        "scheduled-action-id",
			ActionType:      fleetapi.ActionTypeUpgrade,
			ActionStartTime: time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			Data: fleetapi.ActionUpgradeData{
				Version:   "9.3.0",
				SourceURI: "https://test-uri.test.com",
			},
		}

		dispatchDone := make(chan struct{})
		go func() {
			d.Dispatch(ctx, detailsSetter, ack, initialScheduledUpgradeAction)
			close(dispatchDone)
		}()
		select {
		case err := <-d.Errors():
			t.Fatalf("Unexpected error from Dispatch: %v", err)
		case <-dispatchDone:
		}

		// make sure that the upgrade details reported are matching our expectations
		require.NotNilf(t, gotDetails, "upgrade details should not be nil")
		assert.Equal(t, initialScheduledUpgradeAction.ActionID, gotDetails.ActionID)
		assert.Equal(t, details.StateScheduled, gotDetails.State)
		assert.Equal(t, initialScheduledUpgradeAction.Data.Version, gotDetails.TargetVersion)
		assert.Empty(t, gotDetails.Metadata.ErrorMsg)

		// affect directly the queue to get the dispatcher to actually dispatch our action
		removedItems := actionQueue.Cancel(initialScheduledUpgradeAction.ActionID)
		require.Equal(t, 1, removedItems)
		actionNewStartTime := time.Now().Add(-5 * time.Minute).UTC()
		initialScheduledUpgradeAction.ActionStartTime = actionNewStartTime.Format(time.RFC3339)
		actionQueue.Add(initialScheduledUpgradeAction, actionNewStartTime.Unix())

		go func() {
			d.Dispatch(ctx, detailsSetter, ack)
		}()
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error from Dispatch: %v", err)
		}

		// make sure that upgrade details are still reported as scheduled but with a non-empty error
		require.NotNilf(t, gotDetails, "upgrade details should not be nil")
		assert.Equal(t, initialScheduledUpgradeAction.ActionID, gotDetails.ActionID)
		assert.Equal(t, details.StateScheduled, gotDetails.State)
		assert.Equal(t, initialScheduledUpgradeAction.Data.Version, gotDetails.TargetVersion)
		assert.NotEmpty(t, gotDetails.Metadata.ErrorMsg)

		// issue a brand-new upgrade action
		newUpgradeAction := &fleetapi.ActionUpgrade{
			ActionID:   "upgrade-action-id",
			ActionType: fleetapi.ActionTypeUpgrade,
			Data: fleetapi.ActionUpgradeData{
				Version:   "9.3.0",
				SourceURI: "https://test-uri.test.com",
			},
		}
		def.On("Handle",
			mock.Anything, mock.Anything, mock.Anything).
			Return(nil).Once()

		detailsSetter = func(upgradeDetails *details.Details) {
			gotDetails = upgradeDetails
		}
		go func() {
			d.Dispatch(ctx, detailsSetter, ack, newUpgradeAction)
		}()
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error from Dispatch: %v", err)
		}
		require.Nil(t, gotDetails)

		// make sure that the action queue doesn't have any actions
		assert.Empty(t, actionQueue.Actions())
		def.AssertExpectations(t)
		saver.AssertExpectations(t)
	})
}

func Test_ActionDispatcher_scheduleRetry(t *testing.T) {
	ack := noop.New()
	def := &mockHandler{}

	t.Run("no more attempts", func(t *testing.T) {
		saver := &mockSaver{}

		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		action := &mockRetryableAction{}
		action.On("ID").Return("id")
		action.On("RetryAttempt").Return(len(d.rt.steps)).Once()
		action.On("SetRetryAttempt", mock.Anything).Once()
		action.On("Type").Return(fleetapi.ActionTypeUpgrade).Once()
		action.On("GetError").Return(nil).Once()

		upgradeDetailsNeedUpdate := false
		d.scheduleRetry(context.Background(), action, ack, &upgradeDetailsNeedUpdate)
		assert.False(t, upgradeDetailsNeedUpdate)

		saver.AssertExpectations(t)
		action.AssertExpectations(t)
	})

	t.Run("schedule an attempt", func(t *testing.T) {
		saver := &mockSaver{}
		saver.On("Save").Return(nil).Once()
		saver.On("SetQueue", mock.Anything).Once()

		actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
		require.NoError(t, err)

		d, err := New(nil, t.TempDir(), def, actionQueue)
		require.NoError(t, err)

		action := &mockRetryableAction{}
		action.On("ID").Return("id")
		action.On("RetryAttempt").Return(0).Once()
		action.On("SetRetryAttempt", 1).Once()
		action.On("SetStartTime", mock.Anything).Once()
		action.On("Type").Return(fleetapi.ActionTypeUpgrade).Twice()
		action.On("GetError").Return(nil).Once()

		upgradeDetailsNeedUpdate := false
		d.scheduleRetry(context.Background(), action, ack, &upgradeDetailsNeedUpdate)
		assert.True(t, upgradeDetailsNeedUpdate)

		saver.AssertExpectations(t)
		action.AssertExpectations(t)
	})
}

func TestGetQueuedUpgradeDetails(t *testing.T) {
	now := time.Now().UTC()
	later := now.Add(3 * time.Hour)
	laterTruncate := later.Truncate(time.Second)
	muchLater := later.Add(3 * time.Hour)
	before := now.Add(-3 * time.Hour)

	cases := map[string]struct {
		actions           []fleetapi.ScheduledAction
		expectedDetails   *details.Details
		expectedErrLogMsg string
	}{
		"no_scheduled_upgrades": {
			actions: []fleetapi.ScheduledAction{
				&fleetapi.ActionUpgrade{
					ActionID: "action1",
					Data: fleetapi.ActionUpgradeData{
						Version: "8.12.3",
					},
				},
			},
			expectedErrLogMsg: "failed to get start time for scheduled upgrade action [id = action1]",
		},
		"one_scheduled_upgrade": {
			actions: []fleetapi.ScheduledAction{
				&fleetapi.ActionUpgrade{
					ActionID:         "action2",
					ActionStartTime:  later.Format(time.RFC3339),
					ActionExpiration: muchLater.Format(time.RFC3339),
					Data: fleetapi.ActionUpgradeData{
						Version: "8.13.0",
					},
				},
			},
			expectedDetails: &details.Details{
				TargetVersion: "8.13.0",
				State:         details.StateScheduled,
				ActionID:      "action2",
				Metadata: details.Metadata{
					ScheduledAt: &laterTruncate,
				},
			},
		},
		"one_scheduled_upgrade_but_expired": {
			actions: []fleetapi.ScheduledAction{
				&fleetapi.ActionUpgrade{
					ActionID:         "action1",
					ActionStartTime:  before.Format(time.RFC3339),
					ActionExpiration: before.Format(time.RFC3339),
					Data: fleetapi.ActionUpgradeData{
						Version: "8.13.0",
					},
				},
			},
			expectedDetails: &details.Details{
				TargetVersion: "8.13.0",
				State:         details.StateFailed,
				ActionID:      "action1",
				Metadata: details.Metadata{
					ErrorMsg: fmt.Sprintf(`upgrade action "action1" expired on %s`, before.Format(time.RFC3339)),
				},
			},
		},
		"many_scheduled_upgrades": {
			actions: []fleetapi.ScheduledAction{
				&fleetapi.ActionUpgrade{
					ActionID:         "action3",
					ActionStartTime:  muchLater.Format(time.RFC3339),
					ActionExpiration: muchLater.Format(time.RFC3339),
					Data: fleetapi.ActionUpgradeData{
						Version: "8.14.1",
					},
				},
				&fleetapi.ActionUpgrade{
					ActionID:         "action4",
					ActionStartTime:  later.Format(time.RFC3339),
					ActionExpiration: muchLater.Format(time.RFC3339),
					Data: fleetapi.ActionUpgradeData{
						Version: "8.13.5",
					},
				},
			},
			expectedDetails: &details.Details{
				TargetVersion: "8.13.5",
				State:         details.StateScheduled,
				ActionID:      "action4",
				Metadata: details.Metadata{
					ScheduledAt: &laterTruncate,
				},
			},
		},
		"many_scheduled_actions_one_upgrade": {
			actions: []fleetapi.ScheduledAction{
				&mockScheduledAction{},
				&fleetapi.ActionUpgrade{
					ActionID:         "action4",
					ActionStartTime:  later.Format(time.RFC3339),
					ActionExpiration: muchLater.Format(time.RFC3339),
					Data: fleetapi.ActionUpgradeData{
						Version: "8.13.5",
					},
				},
				&mockScheduledAction{},
			},
			expectedDetails: &details.Details{
				TargetVersion: "8.13.5",
				State:         details.StateScheduled,
				ActionID:      "action4",
				Metadata: details.Metadata{
					ScheduledAt: &laterTruncate,
				},
			},
		},
		"invalid_time_scheduled_upgrade": {
			actions: []fleetapi.ScheduledAction{
				&fleetapi.ActionUpgrade{
					ActionID:        "action1",
					ActionStartTime: "invalid",
					Data: fleetapi.ActionUpgradeData{
						Version: "8.13.2",
					},
				},
			},
			expectedErrLogMsg: "failed to get start time for scheduled upgrade action [id = action1]",
		},
		"invalid_expiration_time_upgrade": {
			actions: []fleetapi.ScheduledAction{
				&fleetapi.ActionUpgrade{
					ActionID:         "action1",
					ActionExpiration: "invalid",
					ActionStartTime:  later.Format(time.RFC3339),
					Data: fleetapi.ActionUpgradeData{
						Version: "8.13.2",
					},
				},
			},
			expectedErrLogMsg: "failed to get expiration time for scheduled upgrade action [id = action1]",
		},
		"no_expiration_time_upgrade": {
			actions: []fleetapi.ScheduledAction{
				&fleetapi.ActionUpgrade{
					ActionID:         "action1",
					ActionExpiration: "",
					ActionStartTime:  later.Format(time.RFC3339),
					Data: fleetapi.ActionUpgradeData{
						Version: "8.13.2",
					},
				},
			},
			expectedDetails: &details.Details{
				TargetVersion: "8.13.2",
				State:         details.StateScheduled,
				ActionID:      "action1",
				Metadata: details.Metadata{
					ScheduledAt: &laterTruncate,
				},
			},
		},
	}

	saver := &mockSaver{}
	saver.On("Save").Return(nil).Once()
	saver.On("SetQueue", mock.Anything).Once()

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			actionQueue, err := queue.NewActionQueue([]fleetapi.ScheduledAction{}, saver)
			require.NoError(t, err)

			for _, action := range test.actions {
				actionQueue.Add(action, now.UnixMilli())
			}

			log, obs := loggertest.New("report_next_upgrade_details")
			actualDetails := GetScheduledUpgradeDetails(log, actionQueue.Actions(), now)

			if test.expectedDetails == nil {
				assert.Nil(t, actualDetails)
			} else {
				assert.True(t, test.expectedDetails.Equals(actualDetails))
			}

			logs := obs.TakeAll()
			if test.expectedErrLogMsg != "" {
				assert.Len(t, logs, 1)
				assert.Equal(t, zapcore.ErrorLevel, logs[0].Level)
				assert.True(t, strings.HasPrefix(logs[0].Message, test.expectedErrLogMsg))
			} else {
				assert.Empty(t, logs)
			}
		})
	}
}
