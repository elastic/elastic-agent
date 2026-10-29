// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/retrier"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockDispatcher struct {
	mock.Mock
}

func (m *mockDispatcher) Dispatch(ctx context.Context, detailsSetter details.Observer, ack acker.Acker, actions ...fleetapi.Action) {
	m.Called(ctx, detailsSetter, ack, actions)
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
		flushInterval       time.Duration
		contextTimeout      time.Duration
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
		flushInterval:  time.Second,
		contextTimeout: time.Millisecond * 100,
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
			dispatcher.On("Dispatch", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Once()
			return dispatcher
		},
		flushInterval:  time.Second,
		contextTimeout: time.Millisecond * 200,
	}, {
		name: "no gateway actions, dispatcher is flushed",
		mockGateway: func(ch chan []fleetapi.Action) *mockGateway {
			gateway := &mockGateway{}
			gateway.On("Actions").Return((<-chan []fleetapi.Action)(ch))
			return gateway
		},
		mockDispatcher: func() *mockDispatcher {
			dispatcher := &mockDispatcher{}
			dispatcher.On("Dispatch", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Once()
			dispatcher.On("Dispatch", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe() // allow a second call in case there are timing issues in the CI pipeline
			return dispatcher
		},
		flushInterval:  time.Millisecond * 60,
		contextTimeout: time.Millisecond * 100,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && tc.skipOnWindowsReason != "" {
				t.Skip(tc.skipOnWindowsReason)
			}

			ch := make(chan []fleetapi.Action, 1)
			gateway := tc.mockGateway(ch)
			dispatcher := tc.mockDispatcher()
			detailsSetter := func(upgradeDetails *details.Details) {}
			acker := &mockAcker{}

			ctx, cancel := context.WithTimeout(context.Background(), tc.contextTimeout)
			defer cancel()
			runDispatcher(ctx, dispatcher, gateway, detailsSetter, acker, tc.flushInterval)
			assert.Empty(t, ch)

			gateway.AssertExpectations(t)
			dispatcher.AssertExpectations(t)
			acker.AssertExpectations(t)
		})
	}
}

type fakeClientSetter struct {
	clientCh chan client.Sender
}

func (f *fakeClientSetter) SetClient(c client.Sender) {
	f.clientCh <- c
}

type fakeUpgradeManager struct {
	coordinator.UpgradeManager
	acked bool
}

func (f *fakeUpgradeManager) Ack(_ context.Context, _ acker.Acker) error {
	f.acked = true
	return nil
}

func (f *fakeUpgradeManager) MarkerWatcher() upgrade.MarkerWatcher {
	return nil
}

func newTestManagedConfigManager(t *testing.T, agentInfo *info.MockAgent, ss *store.StateStore) (*managedConfigManager, *fakeClientSetter, *fakeUpgradeManager) {
	t.Helper()
	log, _ := loggertest.New("managed")

	rollbacksSource := ttl.NewMockReadOnlySource(t)
	rollbacksSource.EXPECT().GetAll().Return(nil, nil, nil).Maybe()

	fleetClient, err := remote.NewWithConfig(log, remote.DefaultClientConfig(), nil)
	require.NoError(t, err)

	cfg := configuration.DefaultConfiguration()
	setter := &fakeClientSetter{clientCh: make(chan client.Sender, 1)}
	upgradeMgr := &fakeUpgradeManager{}
	m, err := newManagedConfigManager(log, agentInfo, nil, cfg, nil, nil, 0, "", fleetClient, nil, nil, retrier.New(nil, log), ss, nil, rollbacksSource, setter)
	require.NoError(t, err)
	m.coord = coordinator.New(log, cfg, logger.DefaultLogLevel, agentInfo, component.RuntimeSpecs{}, nil, upgradeMgr, nil, nil, nil, nil, nil, true, nil, nil, nil)
	return m, setter, upgradeMgr
}

func TestManagedConfigManager_Run(t *testing.T) {
	m, _, _ := newTestManagedConfigManager(t, info.NewMockAgent(t), newTestStateStore(t))
	m.coord = nil
	require.ErrorContains(t, m.Run(t.Context()), "coord must be set", "Run should require a coordinator")

	ss := newTestStateStore(t)
	ss.SetAction(&fleetapi.ActionUnenroll{ActionID: "unenroll", ActionType: fleetapi.ActionTypeUnenroll})
	m, setter, _ := newTestManagedConfigManager(t, info.NewMockAgent(t), ss)
	require.NoError(t, m.Run(t.Context()), "Run should return without error when previously unenrolled")
	assert.Empty(t, setter.clientCh, "Run should not set the client when previously unenrolled")

	reloadErr := errors.New("reload failed")
	agentInfo := info.NewMockAgent(t)
	agentInfo.EXPECT().ReloadID(mock.Anything).Return(reloadErr)
	m, setter, _ = newTestManagedConfigManager(t, agentInfo, newTestStateStore(t))
	require.ErrorIs(t, m.Run(t.Context()), reloadErr, "Run should return the error from reloading the agent ID")
	assert.Empty(t, setter.clientCh, "Run should not set the client when reloading the agent ID fails")

	agentInfo = info.NewMockAgent(t)
	agentInfo.EXPECT().ReloadID(mock.Anything).Return(nil)
	agentInfo.EXPECT().AgentID().Return("agent-id")
	m, setter, upgradeMgr := newTestManagedConfigManager(t, agentInfo, newTestStateStore(t))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- m.Run(ctx)
	}()

	select {
	case c := <-setter.clientCh:
		assert.Same(t, m.client, c)
	case <-time.After(10 * time.Second):
		t.Fatal("SetClient was not called on the initial client setter")
	}
	assert.True(t, upgradeMgr.acked, "pending upgrade should be acked on startup")

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			require.ErrorIs(t, err, context.Canceled)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func newTestStateStore(t *testing.T) *store.StateStore {
	t.Helper()
	log, _ := loggertest.New("state_store")
	s, err := storage.NewDiskStore(filepath.Join(t.TempDir(), "state.json"))
	require.NoError(t, err)
	ss, err := store.NewStateStore(log, s)
	require.NoError(t, err)
	return ss
}
