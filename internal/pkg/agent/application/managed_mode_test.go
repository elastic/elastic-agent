// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockDispatcher struct {
	mock.Mock
}

func (m *mockDispatcher) Dispatch(ctx context.Context, ack acker.Acker, actions ...fleetapi.Action) {
	m.Called(ctx, ack, actions)
}

func (m *mockDispatcher) Errors() <-chan error {
	args := m.Called()
	return args.Get(0).(<-chan error)
}

type mockGateway struct {
	mock.Mock
}

func (m *mockGateway) Run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockGateway) Errors() <-chan error {
	args := m.Called()
	return args.Get(0).(<-chan error)
}

func (m *mockGateway) Actions() <-chan []fleetapi.Action {
	args := m.Called()
	return args.Get(0).(<-chan []fleetapi.Action)
}

func (m *mockGateway) SetClient(c client.Sender) {
	m.Called(c)
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

func Test_runDispatcher(t *testing.T) {
	tests := []struct {
		name                string
		mockGateway         func(chan []fleetapi.Action) *mockGateway
		mockDispatcher      func() *mockDispatcher
		interval            time.Duration
		skipOnWindowsReason string
	}{{
		name: "dispatcher not called",
		mockGateway: func(ch chan []fleetapi.Action) *mockGateway {
			gateway := &mockGateway{}
			gateway.On("Actions").Return((<-chan []fleetapi.Action)(ch))
			return gateway
		},
		mockDispatcher: func() *mockDispatcher {
			dispatcher := &mockDispatcher{}
			return dispatcher
		},
		interval: time.Second,
	}, {
		name: "gateway actions passed",
		mockGateway: func(ch chan []fleetapi.Action) *mockGateway {
			ch <- []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "test"}}
			gateway := &mockGateway{}
			gateway.On("Actions").Return((<-chan []fleetapi.Action)(ch))
			return gateway
		},
		mockDispatcher: func() *mockDispatcher {
			dispatcher := &mockDispatcher{}
			dispatcher.On("Dispatch", mock.Anything, mock.Anything, mock.Anything).Once()
			return dispatcher
		},
		interval: time.Second,
	}, {
		name:                "no gateway actions, dispatcher is flushed",
		skipOnWindowsReason: "Flaky test: https://github.com/elastic/elastic-agent/issues/2585",
		mockGateway: func(ch chan []fleetapi.Action) *mockGateway {
			gateway := &mockGateway{}
			gateway.On("Actions").Return((<-chan []fleetapi.Action)(ch))
			return gateway
		},
		mockDispatcher: func() *mockDispatcher {
			dispatcher := &mockDispatcher{}
			dispatcher.On("Dispatch", mock.Anything, mock.Anything, mock.Anything).Once()
			return dispatcher
		},
		interval: time.Millisecond * 60,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && tc.skipOnWindowsReason != "" {
				t.Skip(tc.skipOnWindowsReason)
			}

			ch := make(chan []fleetapi.Action, 1)
			gateway := tc.mockGateway(ch)
			dispatcher := tc.mockDispatcher()
			acker := &mockAcker{}

			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
			defer cancel()
			runDispatcher(ctx, dispatcher, gateway, acker, tc.interval)
			assert.Empty(t, ch)

			gateway.AssertExpectations(t)
			dispatcher.AssertExpectations(t)
			acker.AssertExpectations(t)
		})
	}
}
