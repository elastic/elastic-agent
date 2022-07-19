// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dispatcher

import (
	"context"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

func TestActionDispatcher(t *testing.T) {
	ack := noop.New()

	t.Run("Success to dispatch multiples events", func(t *testing.T) {
		ctx := context.Background()
		def := &mockHandler{}
		d, err := New(nil, def)
		require.NoError(t, err)

		success1 := &mockHandler{}
		success2 := &mockHandler{}

		err = d.Register(&mockAction{}, success1)
		require.NoError(t, err)
		err = d.Register(&mockOtherAction{}, success2)
		require.NoError(t, err)

		action1 := &mockAction{}
		action2 := &mockOtherAction{}

		// TODO better matching for actions
		success1.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		success2.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		err = d.Dispatch(ctx, ack, action1, action2)
		require.NoError(t, err)

		success1.AssertExpectations(t)
		success2.AssertExpectations(t)
		def.AssertNotCalled(t, "Handle", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Unknown action are caught by the unknown handler", func(t *testing.T) {
		def := &mockHandler{}
		def.On("Handle", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		ctx := context.Background()
		d, err := New(nil, def)
		require.NoError(t, err)

		action := &mockUnknownAction{}
		err = d.Dispatch(ctx, ack, action)

		require.NoError(t, err)
		def.AssertExpectations(t)
	})

	t.Run("Could not register two handlers on the same action", func(t *testing.T) {
		success1 := &mockHandler{}
		success2 := &mockHandler{}

		def := &mockHandler{}
		d, err := New(nil, def)
		require.NoError(t, err)

		err = d.Register(&mockAction{}, success1)
		require.NoError(t, err)

		err = d.Register(&mockAction{}, success2)
		require.Error(t, err)
	})
}
