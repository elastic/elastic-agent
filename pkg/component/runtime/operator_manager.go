// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"sync"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/atomic"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type watchResult struct {
	Create bool
	Update bool
	Stop   bool
	Err    error
	Comp   component.Component
}

const DefaultDaemonSetSuffix = "defaultds"

type WatchChan chan chan watchResult

// Manager for the entire runtime of operating components.
type OperatorManager struct {
	ctx        context.Context
	logger     *logger.Logger
	baseLogger *logger.Logger
	watchCh    WatchChan
	updateMx   sync.Mutex

	currentMx sync.RWMutex
	current   map[string]*containerRuntime

	shuttingDown atomic.Bool
}

// NewManager creates a new manager.
func NewOperatorManager(
	logger,
	baseLogger *logger.Logger,
) (*OperatorManager, error) {
	m := &OperatorManager{
		ctx:        context.Background(),
		logger:     logger,
		baseLogger: baseLogger,
		watchCh:    make(WatchChan),
		current:    make(map[string]*containerRuntime),
	}
	return m, nil
}

// Run runs the manager's grpc server, implementing the
// calls CheckinV2 and Actions (with a legacy handler for Checkin
// that returns an error).
//
// Called on its own goroutine from Coordinator.runner.
//
// Blocks until the context is done.
func (m *OperatorManager) Run(ctx context.Context) error {
	m.ctx = ctx
	m.shuttingDown.Store(false)

	<-ctx.Done()

	m.shuttingDown.Store(true)

	return fmt.Errorf("not implemented")
}

// Run runs the manager.

// Errors returns the channel to listen to errors on.
//
// A manager should send a nil error to clear its previous error when it should no longer report as an error.
func (m *OperatorManager) Errors() <-chan error {
	return nil
}

// Update updates the current components model.
func (m *OperatorManager) Update(model component.Model) error {
	shuttingDown := m.shuttingDown.Load()
	if shuttingDown {
		// ignore any updates once shutdown started
		return nil
	}

	return m.update(m.logger, model, nil)
}

// State returns the current components model state.
func (m *OperatorManager) State() []ComponentComponentState {
	m.currentMx.RLock()
	defer m.currentMx.RUnlock()

	states := make([]ComponentComponentState, 0, len(m.current))
	for _, crs := range m.current {

		cs := ComponentComponentState{
			Component: crs.comp,
			State: ComponentState{
				State:   client.UnitStateHealthy, // TODO: check state
				Message: "",
				Units:   make(map[ComponentUnitKey]ComponentUnitState), // TODO: get units from config
			},
		}
		for _, unit := range crs.comp.Units {
			key := ComponentUnitKey{
				UnitType: unit.Type,
				UnitID:   unit.ID,
			}
			cs.State.Units[key] = ComponentUnitState{
				State: client.UnitStateHealthy, // TODO:
			}
		}

		states = append(states, cs)
	}
	return states
}

// PerformAction executes an action on a unit.
func (m *OperatorManager) PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error) {
	return nil, fmt.Errorf("not implemented")
}

// SubscribeAll provides an interface to watch for changes in all components.
func (m *OperatorManager) SubscribeAll(context.Context) *SubscriptionAll {
	return nil // TODO: proper implementation
}

// PerformDiagnostics executes the diagnostic action for the provided units. If no units are provided then
// it performs diagnostics for all current units.
func (m *OperatorManager) PerformDiagnostics(context.Context, ...ComponentUnitDiagnosticRequest) []ComponentUnitDiagnostic {
	return nil
}

// PerformComponentDiagnostics executes the diagnostic action for the provided components. If no components are provided,
// then it performs the diagnostics for all current units.
func (m *OperatorManager) PerformComponentDiagnostics(ctx context.Context, additionalMetrics []cproto.AdditionalDiagnosticRequest, req ...component.Component) ([]ComponentDiagnostic, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *OperatorManager) Watch() WatchChan {
	return m.watchCh
}

func (m *OperatorManager) update(log *logger.Logger, model component.Model, cfg map[string]interface{}) error {
	// ensure that only one `update` can occur at the same time
	m.updateMx.Lock()
	defer m.updateMx.Unlock()

	reconciliationCh := make(chan watchResult)
	m.watchCh <- reconciliationCh
	defer close(reconciliationCh)

	touched := make(map[string]bool)
	newComponents := make([]component.Component, 0, len(model.Components))
	existingComponents := make([]component.Component, 0, len(model.Components))

	// compute new updated
	for _, originalComp := range model.Components {
		for _, comp := range groupComponents(log, originalComp) {
			m.logger.Debugf("considering component", comp.ID)
			if _, handled := touched[comp.ID]; handled {
				continue
			}

			touched[comp.ID] = true
			m.currentMx.RLock()
			_, ok := m.current[comp.ID]
			m.currentMx.RUnlock()
			if ok {
				m.logger.Debugf("adding for update", comp.ID)
				// existing component; send runtime updated value
				existingComponents = append(existingComponents, comp)
				continue
			}

			m.logger.Debugf("adding for start", comp.ID)
			newComponents = append(newComponents, comp)
		}
	}
	// compute removed components
	var stop []*containerRuntime
	m.currentMx.RLock()
	for id, existing := range m.current {
		// skip if already touched (meaning it still existing)
		if _, done := touched[id]; done {
			continue
		}
		// component was removed (time to clean it up)

		m.logger.Debugf("adding for stop", id)
		stop = append(stop, existing)
	}
	m.currentMx.RUnlock()

	// Act
	var err error
	if stepErr := m.stopRuntimes(stop, reconciliationCh); stepErr != nil {
		err = stepErr
	}

	if stepErr := m.updateRuntimes(existingComponents, reconciliationCh); stepErr != nil {
		err = stepErr
	}

	if stepErr := m.startRuntimes(newComponents, reconciliationCh); stepErr != nil {
		err = stepErr
	}

	return err
}

func groupComponents(log *logger.Logger, comp component.Component) []component.Component {
	grouping := make(map[string][]component.Unit)
	for _, unit := range comp.Units {
		if unit.Type == client.UnitTypeOutput {
			// TODO: spin up shipper and expose service for components to connect,
			// for now shipper per grouping
			continue
		}
		k8sConfig, isCustom := unit.Config.Source.Fields["kubernetes"]
		if !isCustom {
			if _, ok := grouping[DefaultDaemonSetSuffix]; !ok {
				grouping[DefaultDaemonSetSuffix] = make([]component.Unit, 0, 1)
			}
			grouping[DefaultDaemonSetSuffix] = append(grouping[DefaultDaemonSetSuffix], unit)
			continue
		}
		hash := sha256.New()
		hash.Write([]byte(k8sConfig.String()))
		key := fmt.Sprintf("%x", hash.Sum(nil))

		if _, ok := grouping[key]; !ok {
			grouping[key] = make([]component.Unit, 0, 1)
		}
		grouping[key] = append(grouping[key], unit)
	}

	components := make([]component.Component, 0, len(grouping))
	for key, units := range grouping {
		suffix := key
		if len(suffix) > 8 {
			suffix = suffix[:8]
		}

		newComp := component.Component{
			ID:          fmt.Sprintf("%s-%s", comp.ID, suffix),
			Err:         comp.Err,
			InputSpec:   comp.InputSpec,
			ShipperSpec: comp.ShipperSpec,
			InputType:   comp.InputType,
			OutputType:  comp.OutputType,
			Features:    comp.Features,
			ShipperRef:  comp.ShipperRef,
			Units:       units,
		}

		if kubernetesConfig, found := units[0].Config.Source.Fields["kubernetes"]; found {
			if k8sMap := kubernetesConfig.GetStructValue(); k8sMap != nil {
				newComp.Kubernetes = k8sMap.AsMap()
			}
		}

		components = append(components, newComp)
	}

	return components
}

func (m *OperatorManager) startRuntimes(rr []component.Component, recCh chan watchResult) error {
	var err error

	m.logger.Debugf("starting %d components", len(rr))
	for _, comp := range rr {
		cr, crErr := newContainerRuntime(comp, m.logger)
		if crErr != nil {
			err = crErr
			m.logger.Errorf("Created runtime and failed %v", err)
			continue
		}
		m.currentMx.Lock()
		m.logger.Debugf("adding to current %s", cr.ID())
		m.current[comp.ID] = cr
		m.currentMx.Unlock()

		m.logger.Debugf("Created runtime and running")
		runErr := cr.Run(m.ctx, recCh)
		if runErr != nil {
			err = runErr
			m.logger.Errorf("Created runtime ran and failed %v", err)
			continue
		}
	}

	return err
}

func (m *OperatorManager) updateRuntimes(rr []component.Component, recCh chan watchResult) error {
	var err error
	m.logger.Debugf("updating %d components", len(rr))
	for _, comp := range rr {
		cr, ok := m.current[comp.ID]
		if !ok {
			// does not happen
			continue
		}

		if compHash(cr.comp) == compHash(comp) {
			continue
		}

		// Component runtime will handle updating to same policy, no need to check
		runErr := cr.Update(m.ctx, comp, recCh)
		if runErr != nil {
			err = runErr
			continue
		}
	}

	return err
}

func compHash(comp component.Component) string {
	out, _ := yaml.Marshal(comp)
	hash := sha512.New()
	hash.Write(out)

	return string(hash.Sum(nil))
}

func (m *OperatorManager) stopRuntimes(rr []*containerRuntime, recCh chan watchResult) error {
	var err error
	m.logger.Debugf("stopping %d components", len(rr))
	for _, cr := range rr {
		runErr := cr.Stop(m.ctx, recCh)
		if runErr != nil {
			err = runErr
			continue
		}

		// remove after all is removed
		m.currentMx.Lock()
		m.logger.Debugf(">>> removing from current %s", cr.ID())
		delete(m.current, cr.ID())
		m.currentMx.Unlock()
	}

	return err
}
