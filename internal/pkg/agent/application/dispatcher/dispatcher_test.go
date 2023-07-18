// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dispatcher

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop"
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

type mockQueue struct {
	mock.Mock
}

func (m *mockQueue) Add(action fleetapi.ScheduledAction, n int64) {
	m.Called(action, n)
}

func (m *mockQueue) DequeueActions() []fleetapi.ScheduledAction {
	args := m.Called()
	return args.Get(0).([]fleetapi.ScheduledAction)
}

func (m *mockQueue) CancelType(t string) int {
	args := m.Called(t)
	return args.Int(0)
}

func (m *mockQueue) Save() error {
	args := m.Called()
	return args.Error(0)
}

func TestActionDispatcher(t *testing.T) {
	ack := noop.New()

	t.Run("Success to dispatch multiples events", func(t *testing.T) {
		ctx := context.Background()
		def := &mockHandler{}
		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("DequeueActions").Return([]fleetapi.ScheduledAction{}).Once()
		d, err := New(nil, def, queue)
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
		go d.Dispatch(dispatchCtx, ack, action1, action2)
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		success1.AssertExpectations(t)
		success2.AssertExpectations(t)
		def.AssertNotCalled(t, "Handle", mock.Anything, mock.Anything, mock.Anything)
		queue.AssertExpectations(t)
	})

	t.Run("Unknown action are caught by the unknown handler", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		ctx := context.Background()
		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("DequeueActions").Return([]fleetapi.ScheduledAction{}).Once()
		d, err := New(nil, def, queue)
		require.NoError(t, err)

		action := &mockOtherAction{}
		action.On("Type").Return("action")
		action.On("ID").Return("id")

		dispatchCtx, cancelFn := context.WithCancel(ctx)
		defer cancelFn()
		go d.Dispatch(dispatchCtx, ack, action)
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		def.AssertExpectations(t)
		queue.AssertExpectations(t)
	})

	t.Run("Could not register two handlers on the same action", func(t *testing.T) {
		success1 := &mockHandler{}
		success2 := &mockHandler{}

		def := &mockHandler{}
		queue := &mockQueue{}
		d, err := New(nil, def, queue)
		require.NoError(t, err)

		err = d.Register(&mockAction{}, success1)
		require.NoError(t, err)

		err = d.Register(&mockAction{}, success2)
		require.Error(t, err)
		queue.AssertExpectations(t)
	})

	t.Run("Dispatched action is queued", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("DequeueActions").Return([]fleetapi.ScheduledAction{}).Once()
		queue.On("Add", mock.Anything, mock.Anything).Once()

		d, err := New(nil, def, queue)
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
		go d.Dispatch(dispatchCtx, ack, action1, action2)
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		def.AssertExpectations(t)
		queue.AssertExpectations(t)
	})

	t.Run("Cancel queued action", func(t *testing.T) {
		def := &mockHandler{}
		calledCh := make(chan bool)
		call := def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		call.RunFn = func(_ mock.Arguments) {
			calledCh <- true
		}

		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("DequeueActions").Return([]fleetapi.ScheduledAction{}).Once()

		d, err := New(nil, def, queue)
		require.NoError(t, err)
		err = d.Register(&mockAction{}, def)
		require.NoError(t, err)

		action := &mockAction{}
		action.On("Type").Return(fleetapi.ActionTypeCancel)
		action.On("ID").Return("id")

		dispatchCtx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		go d.Dispatch(dispatchCtx, ack, action)
		select {
		case err := <-d.Errors():
			t.Fatalf("Unexpected error: %v", err)
		case <-calledCh:
			// Handle was called, expected
		case <-time.After(1 * time.Second):
			t.Fatal("mock Handle never called")
		}
		def.AssertExpectations(t)
		queue.AssertExpectations(t)
	})

	t.Run("Retrieve actions from queue", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Twice()

		action1 := &mockScheduledAction{}
		action1.On("StartTime").Return(time.Time{}, fleetapi.ErrNoStartTime)
		action1.On("Expiration").Return(time.Now().Add(time.Hour), fleetapi.ErrNoStartTime)
		action1.On("Type").Return(fleetapi.ActionTypeCancel)
		action1.On("ID").Return("id")

		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("DequeueActions").Return([]fleetapi.ScheduledAction{action1}).Once()

		d, err := New(nil, def, queue)
		require.NoError(t, err)
		err = d.Register(&mockAction{}, def)
		require.NoError(t, err)

		action2 := &mockAction{}
		action2.On("Type").Return(fleetapi.ActionTypeCancel)
		action2.On("ID").Return("id")

		dispatchCtx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		go d.Dispatch(dispatchCtx, ack, action2)
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		def.AssertExpectations(t)
		queue.AssertExpectations(t)
	})

	t.Run("Retrieve no actions from queue", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("DequeueActions").Return([]fleetapi.ScheduledAction{}).Once()

		d, err := New(nil, def, queue)
		require.NoError(t, err)
		err = d.Register(&mockAction{}, def)
		require.NoError(t, err)

		dispatchCtx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		go d.Dispatch(dispatchCtx, ack)
		select {
		case err := <-d.Errors():
			t.Fatalf("Unexpected error: %v", err)
		case <-time.After(500 * time.Microsecond):
			// we're not expecting any reset
		}
		def.AssertNotCalled(t, "Handle", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Dispatch of a retryable action returns an error", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("test error")).Once()

		queue := &mockQueue{}
		queue.On("Save").Return(nil).Twice()
		queue.On("DequeueActions").Return([]fleetapi.ScheduledAction{}).Once()
		queue.On("Add", mock.Anything, mock.Anything).Once()

		d, err := New(nil, def, queue)
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

		dispatchCtx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		go d.Dispatch(dispatchCtx, ack, action)
		if err := <-d.Errors(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		def.AssertExpectations(t)
		queue.AssertExpectations(t)
		action.AssertExpectations(t)
	})

	t.Run("Dispatch multiples events returns one error", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("test error")).Once()
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("DequeueActions").Return([]fleetapi.ScheduledAction{}).Once()

		d, err := New(nil, def, queue)
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
		dispatchCtx, cancelFn := context.WithCancel(context.Background())
		defer cancelFn()
		go d.Dispatch(dispatchCtx, ack, action1, action2)
		time.Sleep(time.Millisecond * 200)
		select {
		case <-d.Errors():
		default:
			t.Fatal("Expected error")
		}
		time.Sleep(time.Millisecond * 200)
		select {
		case <-d.Errors():
			t.Fatal(err)
		default:
		}

		def.AssertExpectations(t)
		queue.AssertExpectations(t)
	})

	t.Run("Dispatch multiples events in separate batch returns one error second one resets it", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("test error")).Once()
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		queue := &mockQueue{}
		queue.On("Save").Return(nil).Times(2)
		queue.On("DequeueActions").Return([]fleetapi.ScheduledAction{}).Times(2)

		d, err := New(nil, def, queue)
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
		go d.Dispatch(dispatchCtx1, ack, action1)
		select {
		case err := <-d.Errors():
			if err == nil {
				t.Fatal("Expecting error")
			}
		case <-time.After(300 * time.Millisecond):
		}

		dispatchCtx2, cancelFn2 := context.WithCancel(context.Background())
		defer cancelFn2()
		go d.Dispatch(dispatchCtx2, ack, action2)
		select {
		case err := <-d.Errors():
			if err != nil {
				t.Fatal("Unexpected error")
			}
		case <-time.After(300 * time.Millisecond):
		}

		def.AssertExpectations(t)
		queue.AssertExpectations(t)
	})
}

func Test_ActionDispatcher_scheduleRetry(t *testing.T) {
	ack := noop.New()
	def := &mockHandler{}

	t.Run("no more attmpts", func(t *testing.T) {
		queue := &mockQueue{}
		d, err := New(nil, def, queue)
		require.NoError(t, err)

		action := &mockRetryableAction{}
		action.On("ID").Return("id")
		action.On("RetryAttempt").Return(len(d.rt.steps)).Once()
		action.On("SetRetryAttempt", mock.Anything).Once()

		d.scheduleRetry(context.Background(), action, ack)
		queue.AssertExpectations(t)
		action.AssertExpectations(t)
	})

	t.Run("schedule an attempt", func(t *testing.T) {
		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("Add", mock.Anything, mock.Anything).Once()
		d, err := New(nil, def, queue)
		require.NoError(t, err)

		action := &mockRetryableAction{}
		action.On("ID").Return("id")
		action.On("RetryAttempt").Return(0).Once()
		action.On("SetRetryAttempt", 1).Once()
		action.On("SetStartTime", mock.Anything).Once()

		d.scheduleRetry(context.Background(), action, ack)
		queue.AssertExpectations(t)
		action.AssertExpectations(t)
	})
}
