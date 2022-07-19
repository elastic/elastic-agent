// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"fmt"
	handlers2 "github.com/elastic/elastic-agent/internal/pkg/agent/application/actions/handlers"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/dispatcher"
	fleetgateway "github.com/elastic/elastic-agent/internal/pkg/agent/application/gateway/fleet"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/fleet"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/lazy"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/retrier"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/queue"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type managedConfigManager struct {
	log         *logger.Logger
	agentInfo   *info.AgentInfo
	cfg         *configuration.Configuration
	client      *remote.Client
	store       storage.Store
	stateStore  *store.StateStore
	actionQueue *queue.ActionQueue
	coord       *coordinator.Coordinator

	ch    chan coordinator.ConfigChange
	errCh chan error
}

func newManagedConfigManager(
	log *logger.Logger,
	agentInfo *info.AgentInfo,
	cfg *configuration.Configuration,
	storeSaver storage.Store,
) (*managedConfigManager, error) {
	client, err := client.NewAuthWithConfig(log, cfg.Fleet.AccessAPIKey, cfg.Fleet.Client)
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

	actionQueue, err := queue.NewActionQueue(stateStore.Queue())
	if err != nil {
		return nil, fmt.Errorf("unable to initialize action queue: %w", err)
	}

	return &managedConfigManager{
		log:         log,
		agentInfo:   agentInfo,
		cfg:         cfg,
		client:      client,
		store:       storeSaver,
		stateStore:  stateStore,
		actionQueue: actionQueue,
		ch:          make(chan coordinator.ConfigChange),
		errCh:       make(chan error),
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

	// Create the actionDispatcher.
	actionDispatcher, err := newManagedActionDispatcher(m, gatewayCancel)
	if err != nil {
		return err
	}

	// Create ackers to enqueue/retry failed acks
	ack, err := fleet.NewAcker(m.log, m.agentInfo, m.client)
	if err != nil {
		return fmt.Errorf("failed to create acker: %w", err)
	}
	retrier := retrier.New(ack, m.log)
	batchedAcker := lazy.NewAcker(ack, m.log, lazy.WithRetrier(retrier))
	actionAcker := store.NewStateStoreActionAcker(batchedAcker, m.stateStore)

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
	//stateRestored := false
	if len(actions) > 0 && !m.wasUnenrolled() {
		// TODO(ph) We will need an improvement on fleet, if there is an error while dispatching a
		// persisted action on disk we should be able to ask Fleet to get the latest configuration.
		// But at the moment this is not possible because the policy change was acked.
		if err := store.ReplayActions(ctx, m.log, actionDispatcher, actionAcker, actions...); err != nil {
			m.log.Errorf("could not recover state, error %+v, skipping...", err)
		}
		//stateRestored = true
	}

	gateway, err := fleetgateway.New(
		m.log,
		m.agentInfo,
		m.client,
		actionDispatcher,
		actionAcker,
		m.coord,
		m.stateStore,
		m.actionQueue,
	)
	if err != nil {
		return err
	}

	// Proxy errors from the gateway to our own channel.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-gateway.Errors():
				m.errCh <- err
			}
		}
	}()

	// Run the gateway.
	gatewayRun := make(chan bool)
	gatewayErrCh := make(chan error)
	defer func() {
		gatewayCancel()
		<-gatewayRun
	}()
	go func() {
		err := gateway.Run(gatewayCtx)
		close(gatewayRun)
		gatewayErrCh <- err
	}()

	/*
		gateway, err = localgateway.New(ctx, m.log, m.cfg.Fleet, rawConfig, gateway, emit, !stateRestored)
		if err != nil {
			return nil, err
		}
		// add the acker and gateway to setters, so the they can be updated
		// when the hosts for Fleet Server are updated by the policy.
		if cfg.Fleet.Server == nil {
			// setters only set when not running a local Fleet Server
			policyChanger.AddSetter(gateway)
			policyChanger.AddSetter(acker)
		}

		managedApplication.gateway = gateway
	*/

	<-ctx.Done()
	return <-gatewayErrCh
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

func newManagedActionDispatcher(m *managedConfigManager, canceller context.CancelFunc) (*dispatcher.ActionDispatcher, error) {
	actionDispatcher, err := dispatcher.New(m.log, handlers2.NewDefault(m.log))
	if err != nil {
		return nil, err
	}

	policyChanger := handlers2.NewPolicyChange(
		m.log,
		m.agentInfo,
		m.cfg,
		m.store,
		m.ch,
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionPolicyChange{},
		policyChanger,
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionPolicyReassign{},
		handlers2.NewPolicyReassign(m.log),
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionUnenroll{},
		handlers2.NewUnenroll(
			m.log,
			m.ch,
			[]context.CancelFunc{canceller},
			m.stateStore,
		),
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionUpgrade{},
		handlers2.NewUpgrade(m.log, m.coord),
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionSettings{},
		handlers2.NewSettings(
			m.log,
			m.agentInfo,
			m.coord,
		),
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionCancel{},
		handlers2.NewCancel(
			m.log,
			m.actionQueue,
		),
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionApp{},
		handlers2.NewAppAction(m.log, m.coord),
	)

	actionDispatcher.MustRegister(
		&fleetapi.ActionUnknown{},
		handlers2.NewUnknown(m.log),
	)

	return actionDispatcher, nil
}
