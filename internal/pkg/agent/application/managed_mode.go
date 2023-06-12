// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions/handlers"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/dispatcher"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/gateway"
	fleetgateway "github.com/elastic/elastic-agent/internal/pkg/agent/application/gateway/fleet"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/fleet"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/lazy"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/retrier"
	fleetclient "github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/uploader"
	"github.com/elastic/elastic-agent/internal/pkg/queue"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/internal/pkg/runner"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// dispatchFlushInterval is the max time between calls to dispatcher.Dispatch
const dispatchFlushInterval = time.Minute * 5

type managedConfigManager struct {
	log              *logger.Logger
	agentInfo        *info.AgentInfo
	cfg              *configuration.Configuration
	client           *remote.Client
	store            storage.Store
	stateStore       *store.StateStore
	actionQueue      *queue.ActionQueue
	dispatcher       *dispatcher.ActionDispatcher
	runtime          *runtime.Manager
	coord            *coordinator.Coordinator
	fleetInitTimeout time.Duration

	ch    chan coordinator.ConfigChange
	errCh chan error
}

func newManagedConfigManager(
	log *logger.Logger,
	agentInfo *info.AgentInfo,
	cfg *configuration.Configuration,
	storeSaver storage.Store,
	runtime *runtime.Manager,
	fleetInitTimeout time.Duration,
) (*managedConfigManager, error) {
	client, err := fleetclient.NewAuthWithConfig(log, cfg.Fleet.AccessAPIKey, cfg.Fleet.Client)
	if err != nil {
		return nil, errors.New(err,
			"fail to create API client",
			errors.TypeNetwork,
			errors.M(errors.MetaKeyURI, cfg.Fleet.Client.Host))
	}

	// Create the state store that will persist the last good policy change on disk.
	stateStore, err := store.NewStateStoreWithMigration(log, paths.AgentActionStoreFile(), paths.AgentStateStoreFile())
	if err != nil {
		return nil, errors.New(err, fmt.Sprintf("fail to read action store '%s'", paths.AgentActionStoreFile()))
	}

	actionQueue, err := queue.NewActionQueue(stateStore.Queue(), stateStore)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize action queue: %w", err)
	}

	actionDispatcher, err := dispatcher.New(log, handlers.NewDefault(log), actionQueue)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize action dispatcher: %w", err)
	}

	return &managedConfigManager{
		log:              log,
		agentInfo:        agentInfo,
		cfg:              cfg,
		client:           client,
		store:            storeSaver,
		stateStore:       stateStore,
		actionQueue:      actionQueue,
		dispatcher:       actionDispatcher,
		runtime:          runtime,
		fleetInitTimeout: fleetInitTimeout,
		ch:               make(chan coordinator.ConfigChange),
		errCh:            make(chan error),
	}, nil
}

func (m *managedConfigManager) Run(ctx context.Context) error {
	// Check setup correctly in application (the actionDispatcher and coord must be set manually)
	if m.coord == nil {
		return errors.New("coord must be set before calling Run")
	}

	// Un-enrolled so we will not do anything.
	if m.wasUnenrolled() {
		m.log.Warnf("Elastic Agent was previously unenrolled. To reactivate please reconfigure or enroll again.")
		return nil
	}

	// Reload ID because of win7 sync issue
	if err := m.agentInfo.ReloadID(); err != nil {
		return err
	}

	// Create context that is cancelled on unenroll.
	gatewayCtx, gatewayCancel := context.WithCancel(ctx)
	defer gatewayCancel()

	// Initialize the actionDispatcher.
	policyChanger := m.initDispatcher(gatewayCancel)

	// Create ackers to enqueue/retry failed acks
	ack, err := fleet.NewAcker(m.log, m.agentInfo, m.client)
	if err != nil {
		return fmt.Errorf("failed to create acker: %w", err)
	}
	retrier := retrier.New(ack, m.log)
	batchedAcker := lazy.NewAcker(ack, m.log, lazy.WithRetrier(retrier))
	actionAcker := store.NewStateStoreActionAcker(batchedAcker, m.stateStore)

	if err := m.coord.AckUpgrade(ctx, actionAcker); err != nil {
		m.log.Warnf("Failed to ack upgrade: %v", err)
	}

	// Run the retrier.
	retrierRun := make(chan bool)
	retrierCtx, retrierCancel := context.WithCancel(ctx)
	defer func() {
		retrierCancel()
		<-retrierRun
	}()
	go func() {
		retrier.Run(retrierCtx)
		close(retrierRun)
	}()

	actions := m.stateStore.Actions()
	stateRestored := false
	if len(actions) > 0 && !m.wasUnenrolled() {
		// TODO(ph) We will need an improvement on fleet, if there is an error while dispatching a
		// persisted action on disk we should be able to ask Fleet to get the latest configuration.
		// But at the moment this is not possible because the policy change was acked.
		m.log.Info("restoring current policy from disk")
		m.dispatcher.Dispatch(ctx, actionAcker, actions...)
		stateRestored = true
	}

	// In the case this Elastic Agent is running a Fleet Server; we need to ensure that
	// the Fleet Server is running before the Fleet gateway is started.
	if m.cfg.Fleet.Server != nil {
		if stateRestored {
			err = m.waitForFleetServer(ctx)
			if err != nil {
				return fmt.Errorf("failed to initialize Fleet Server: %w", err)
			}
		} else {
			err = m.initFleetServer(ctx, m.cfg.Fleet.Server)
			if err != nil {
				return fmt.Errorf("failed to initialize Fleet Server: %w", err)
			}
		}
	}

	gateway, err := fleetgateway.New(
		m.log,
		m.agentInfo,
		m.client,
		actionAcker,
		m.coord,
		m.stateStore,
	)
	if err != nil {
		return err
	}

	// Not running a Fleet Server so the gateway and acker can be changed based on the configuration change.
	if m.cfg.Fleet.Server == nil {
		policyChanger.AddSetter(gateway)
		policyChanger.AddSetter(ack)
	}

	// Proxy errors from the gateway to our own channel.
	gatewayErrorsRunner := runner.Start(context.Background(), func(ctx context.Context) error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case err := <-gateway.Errors():
				m.errCh <- err
			}
		}
	})

	// Run the gateway.
	gatewayRunner := runner.Start(gatewayCtx, func(ctx context.Context) error {
		defer gatewayErrorsRunner.Stop()
		return gateway.Run(ctx)
	})

	go runDispatcher(ctx, m.dispatcher, gateway, actionAcker, dispatchFlushInterval)

	<-ctx.Done()
	return gatewayRunner.Err()
}

// runDispatcher passes actions collected from gateway to dispatcher or calls Dispatch with no actions every flushInterval.
func runDispatcher(ctx context.Context, actionDispatcher dispatcher.Dispatcher, fleetGateway gateway.FleetGateway, actionAcker acker.Acker, flushInterval time.Duration) {
	t := time.NewTimer(flushInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C: // periodically call the dispatcher to handle scheduled actions.
			actionDispatcher.Dispatch(ctx, actionAcker)
			t.Reset(flushInterval)
		case actions := <-fleetGateway.Actions():
			actionDispatcher.Dispatch(ctx, actionAcker, actions...)
			t.Reset(flushInterval)
		}
	}
}

// ActionErrors returns the error channel for actions.
// May return errors for fleet managed errors.
func (m *managedConfigManager) ActionErrors() <-chan error {
	return m.dispatcher.Errors()
}

func (m *managedConfigManager) Errors() <-chan error {
	return m.errCh
}

func (m *managedConfigManager) Watch() <-chan coordinator.ConfigChange {
	return m.ch
}

func (m *managedConfigManager) wasUnenrolled() bool {
	actions := m.stateStore.Actions()
	for _, a := range actions {
		if a.Type() == "UNENROLL" {
			return true
		}
	}
	return false
}

func (m *managedConfigManager) initFleetServer(ctx context.Context, cfg *configuration.FleetServerConfig) error {

	if m.fleetInitTimeout == 0 {
		m.fleetInitTimeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, m.fleetInitTimeout)
	defer cancel()

	m.log.Debugf("injecting basic fleet-server for first start, will wait %s", m.fleetInitTimeout)
	select {
	case <-ctx.Done():
		return fmt.Errorf("timeout while waiting for fleet server start: %w", ctx.Err())
	case m.ch <- &localConfigChange{injectFleetServerInput}:
	}

	return m.waitForFleetServer(ctx)
}

func (m *managedConfigManager) waitForFleetServer(ctx context.Context) error {
	m.log.Debugf("watching Fleet Server component state")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sub := m.runtime.SubscribeAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case compState := <-sub.Ch():
			if compState.Component.InputSpec != nil && compState.Component.InputSpec.InputType == "fleet-server" {
				if fleetServerRunning(compState.State) {
					m.log.With("state", compState.State).Debugf("Fleet Server is running")
					return nil
				}
				m.log.With("state", compState.State).Debugf("Fleet Server is not running")
			}
		}
	}
}

func fleetServerRunning(state runtime.ComponentState) bool {
	if state.State == client.UnitStateHealthy {
		if len(state.Units) == 0 {
			return false
		}
		for _, unit := range state.Units {
			if unit.State != client.UnitStateHealthy {
				return false
			}
		}
		return true
	}
	return false
}

func (m *managedConfigManager) initDispatcher(canceller context.CancelFunc) *handlers.PolicyChangeHandler {
	policyChanger := handlers.NewPolicyChangeHandler(
		m.log,
		m.agentInfo,
		m.cfg,
		m.store,
		m.ch,
	)

	m.dispatcher.MustRegister(
		&fleetapi.ActionPolicyChange{},
		policyChanger,
	)

	m.dispatcher.MustRegister(
		&fleetapi.ActionPolicyReassign{},
		handlers.NewPolicyReassign(m.log),
	)

	m.dispatcher.MustRegister(
		&fleetapi.ActionUnenroll{},
		handlers.NewUnenroll(
			m.log,
			m.ch,
			[]context.CancelFunc{canceller},
			m.stateStore,
		),
	)

	m.dispatcher.MustRegister(
		&fleetapi.ActionUpgrade{},
		handlers.NewUpgrade(m.log, m.coord),
	)

	m.dispatcher.MustRegister(
		&fleetapi.ActionSettings{},
		handlers.NewSettings(
			m.log,
			m.agentInfo,
			m.coord,
		),
	)

	m.dispatcher.MustRegister(
		&fleetapi.ActionCancel{},
		handlers.NewCancel(
			m.log,
			m.actionQueue,
		),
	)

	m.dispatcher.MustRegister(
		&fleetapi.ActionDiagnostics{},
		handlers.NewDiagnostics(
			m.log,
			m.coord,
			m.cfg.Settings.MonitoringConfig.Diagnostics.Limit,
			uploader.New(m.agentInfo.AgentID(), m.client, m.cfg.Settings.MonitoringConfig.Diagnostics.Uploader),
		),
	)

	m.dispatcher.MustRegister(
		&fleetapi.ActionApp{},
		handlers.NewAppAction(m.log, m.coord, m.agentInfo.AgentID()),
	)

	m.dispatcher.MustRegister(
		&fleetapi.ActionUnknown{},
		handlers.NewUnknown(m.log),
	)

	return policyChanger
}
