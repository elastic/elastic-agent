// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dispatcher

import (
	"context"
	"testing"
	"time"

	"go.elastic.co/apm"
	"go.elastic.co/apm/apmtest"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	noopacker "github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop"
)

type mockHandler struct {
	mock.Mock
}

func (h *mockHandler) Handle(ctx context.Context, a fleetapi.Action, acker store.FleetAcker) error {
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
type mockUnknownAction struct {
	mockAction
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
func (m *mockAction) StartTime() (time.Time, error) {
	args := m.Called()
	return args.Get(0).(time.Time), args.Error(1)
}
func (m *mockAction) Expiration() (time.Time, error) {
	args := m.Called()
	return args.Get(0).(time.Time), args.Error(1)
}

type mockAcker struct {
	mock.Mock
}

func (m *mockAcker) Ack(ctx context.Context, action fleetapi.Action) error {
	args := m.Called(ctx, action)
	return args.Error(0)
}

func (m *mockAcker) Commit(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type mockQueue struct {
	mock.Mock
}

func (m *mockQueue) Add(action fleetapi.Action, n int64) {
	m.Called(action, n)
}

func (m *mockQueue) DequeueActions() []fleetapi.Action {
	args := m.Called()
	return args.Get(0).([]fleetapi.Action)
}

func (m *mockQueue) Save() error {
	args := m.Called()
	return args.Error(0)
}

func TestActionDispatcher(t *testing.T) {
	ack := noopacker.NewAcker()

	t.Run("Merges ActionDispatcher ctx cancel and Dispatch ctx value", func(t *testing.T) {
		action1 := &mockAction{}
		action1.On("StartTime").Return(time.Time{}, fleetapi.ErrNoStartTime)
		action1.On("Type").Return("action")
		action1.On("ID").Return("id")
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("DequeueActions").Return([]fleetapi.Action{}).Once()
		span := apmtest.NewRecordingTracer().
			StartTransaction("ignore", "ignore").
			StartSpan("ignore", "ignore", nil)
		ctx1, cancel := context.WithCancel(context.Background())
		ack := &mockAcker{}
		ack.On("Commit", mock.Anything).Run(func(args mock.Arguments) {
			ctx, _ := args.Get(0).(context.Context)
			require.NoError(t, ctx.Err())
			got := apm.SpanFromContext(ctx)
			require.Equal(t, span.TraceContext().Span, got.ParentID())
			cancel() // cancel function from ctx1
			require.Equal(t, ctx.Err(), context.Canceled)
		}).Return(nil)
		d, err := New(ctx1, nil, def, queue)
		require.NoError(t, err)
		ctx2 := apm.ContextWithSpan(context.Background(), span)
		err = d.Dispatch(ctx2, ack, action1)
		require.NoError(t, err)
		ack.AssertExpectations(t)
		queue.AssertExpectations(t)
	})

	t.Run("Success to dispatch multiples events", func(t *testing.T) {
		ctx := context.Background()
		def := &mockHandler{}
		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("DequeueActions").Return([]fleetapi.Action{}).Once()
		d, err := New(ctx, nil, def, queue)
		require.NoError(t, err)

		success1 := &mockHandler{}
		success2 := &mockHandler{}

		err = d.Register(&mockAction{}, success1)
		require.NoError(t, err)
		err = d.Register(&mockOtherAction{}, success2)
		require.NoError(t, err)

		action1 := &mockAction{}
		action1.On("StartTime").Return(time.Time{}, fleetapi.ErrNoStartTime)
		action1.On("Type").Return("action")
		action1.On("ID").Return("id")
		action2 := &mockOtherAction{}
		action2.On("StartTime").Return(time.Time{}, fleetapi.ErrNoStartTime)
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
		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("DequeueActions").Return([]fleetapi.Action{}).Once()
		ctx := context.Background()
		d, err := New(ctx, nil, def, queue)
		require.NoError(t, err)

		action := &mockUnknownAction{}
		action.On("StartTime").Return(time.Time{}, fleetapi.ErrNoStartTime)
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
		d, err := New(context.Background(), nil, def, queue)
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
		queue.On("DequeueActions").Return([]fleetapi.Action{}).Once()
		queue.On("Add", mock.Anything, mock.Anything).Once()

		d, err := New(context.Background(), nil, def, queue)
		require.NoError(t, err)
		err = d.Register(&mockAction{}, def)
		require.NoError(t, err)

		action1 := &mockAction{}
		action1.On("StartTime").Return(time.Time{}, fleetapi.ErrNoStartTime)
		action1.On("Type").Return("action")
		action1.On("ID").Return("id")
		action2 := &mockAction{}
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
		queue.On("DequeueActions").Return([]fleetapi.Action{}).Once()

		d, err := New(context.Background(), nil, def, queue)
		require.NoError(t, err)
		err = d.Register(&mockAction{}, def)
		require.NoError(t, err)

		action := &mockAction{}
		action.On("StartTime").Return(time.Time{}, fleetapi.ErrNoStartTime)
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

		action1 := &mockAction{}
		action1.On("StartTime").Return(time.Time{}, fleetapi.ErrNoStartTime)
		action1.On("Expiration").Return(time.Now().Add(time.Hour), fleetapi.ErrNoStartTime)
		action1.On("Type").Return(fleetapi.ActionTypeCancel)
		action1.On("ID").Return("id")

		queue := &mockQueue{}
		queue.On("Save").Return(nil).Once()
		queue.On("DequeueActions").Return([]fleetapi.Action{action1}).Once()

		d, err := New(context.Background(), nil, def, queue)
		require.NoError(t, err)
		err = d.Register(&mockAction{}, def)
		require.NoError(t, err)

		action2 := &mockAction{}
		action2.On("StartTime").Return(time.Time{}, fleetapi.ErrNoStartTime)
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
		queue.On("DequeueActions").Return([]fleetapi.Action{}).Once()

		d, err := New(context.Background(), nil, def, queue)
		require.NoError(t, err)
		err = d.Register(&mockAction{}, def)
		require.NoError(t, err)

		err = d.Dispatch(context.Background(), ack)
		require.NoError(t, err)
		def.AssertNotCalled(t, "Handle", mock.Anything, mock.Anything, mock.Anything)
	})
}
