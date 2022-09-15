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
func (m *mockScheduledAction) StartTime() (time.Time, error) {
	args := m.Called()
	return args.Get(0).(time.Time), args.Error(1)
}
func (m *mockScheduledAction) Expiration() (time.Time, error) {
	args := m.Called()
	return args.Get(0).(time.Time), args.Error(1)
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

		err = d.Dispatch(ctx, ack, action1, action2)
		require.NoError(t, err)

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
		err = d.Dispatch(ctx, ack, action)

		require.NoError(t, err)
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

		err = d.Dispatch(context.Background(), ack, action1, action2)
		require.NoError(t, err)
		def.AssertExpectations(t)
		queue.AssertExpectations(t)
	})

	t.Run("Cancel queued action", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

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

		err = d.Dispatch(context.Background(), ack, action)
		require.NoError(t, err)
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

		err = d.Dispatch(context.Background(), ack, action2)
		require.NoError(t, err)
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

		err = d.Dispatch(context.Background(), ack)
		require.NoError(t, err)
		def.AssertNotCalled(t, "Handle", mock.Anything, mock.Anything, mock.Anything)
	})
}
