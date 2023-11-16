// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/atomic"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/core/authority"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	// initialCheckinTimeout is the maximum amount of wait time from initial check-in stream to
	// getting the first check-in observed state.
	initialCheckinTimeout = 5 * time.Second
	// maxCheckinMisses is the maximum number of check-in misses a component can miss before it is killed
	// and restarted.
	maxCheckinMisses = 3
	// diagnosticTimeout is the maximum amount of time to wait for a diagnostic response from a unit.
	diagnosticTimeout = time.Minute

	// stopCheckRetryPeriod is a idle time between checks for component stopped state
	stopCheckRetryPeriod = 200 * time.Millisecond
)

var (
	// ErrNoUnit is returned when manager is not controlling this unit.
	ErrNoUnit = errors.New("no unit under control of this manager")
	// ErrNoComponent is returned when manager is not controlling this component
	ErrNoComponent = errors.New("no component under control of this manager")
)

// ComponentComponentState provides a structure to map a component to current component state.
type ComponentComponentState struct {
	Component component.Component `yaml:"component"`
	State     ComponentState      `yaml:"state"`
	LegacyPID string              `yaml:"-"` // To propagate PID for the /processes, and yes, it was a string
}

// ComponentUnitDiagnosticRequest used to request diagnostics from specific unit.
type ComponentUnitDiagnosticRequest struct {
	Component component.Component
	Unit      component.Unit
}

// ComponentUnitDiagnostic provides a structure to map a component/unit to diagnostic results.
type ComponentUnitDiagnostic struct {
	Component component.Component
	Unit      component.Unit
	Results   []*proto.ActionDiagnosticUnitResult
	Err       error
}

// ComponentDiagnostic provides a structure to map a component to a diagnostic result.
type ComponentDiagnostic struct {
	Component component.Component
	Results   []*proto.ActionDiagnosticUnitResult
	Err       error
}

// Manager for the entire runtime of operating components.
type Manager struct {
	proto.UnimplementedElasticAgentServer

	logger     *logger.Logger
	baseLogger *logger.Logger
	ca         *authority.CertificateAuthority
	listenAddr string
	listenPort int
	agentInfo  *info.AgentInfo
	tracer     *apm.Tracer
	monitor    MonitoringManager
	grpcConfig *configuration.GRPCConfig

	// Set when the RPC server is ready to receive requests, for use by tests.
	serverReady *atomic.Bool

	// updateChan forwards component model updates from the public Update method
	// to the internal run loop.
	updateChan chan component.Model

	// Component model update is run asynchronously and pings this channel when
	// finished, so the runtime manager loop knows it's safe to advance to the
	// next update without ever having to block on the result.
	updateDoneChan chan struct{}

	// Next component model update that will be applied, in case we get one
	// while a previous update is still in progress. If we get more than one,
	// keep only the most recent.
	// Only access from the main runtime manager goroutine.
	nextUpdate *component.Model

	// Whether we're already waiting on the results of an update call.
	// If this is true when the run loop finishes, we need to wait for the
	// final update result before shutting down, otherwise the shutdown's
	// update call will conflict.
	// Only access from the main runtime manager goroutine.
	updateInProgress bool

	// currentMx protects access to the current map only
	currentMx sync.RWMutex
	current   map[string]*componentRuntimeState

	shipperConns map[string]*shipperConn

	subMx         sync.RWMutex
	subscriptions map[string][]*Subscription
	subAllMx      sync.RWMutex
	subscribeAll  []*SubscriptionAll

	errCh chan error

	// doneChan is closed when Manager is shutting down to signal that any
	// pending requests should be canceled.
	doneChan chan struct{}
}

// NewManager creates a new manager.
func NewManager(
	logger,
	baseLogger *logger.Logger,
	listenAddr string,
	agentInfo *info.AgentInfo,
	tracer *apm.Tracer,
	monitor MonitoringManager,
	grpcConfig *configuration.GRPCConfig,
) (*Manager, error) {
	ca, err := authority.NewCA()
	if err != nil {
		return nil, err
	}
	m := &Manager{
		logger:         logger,
		baseLogger:     baseLogger,
		ca:             ca,
		listenAddr:     listenAddr,
		agentInfo:      agentInfo,
		tracer:         tracer,
		current:        make(map[string]*componentRuntimeState),
		shipperConns:   make(map[string]*shipperConn),
		subscriptions:  make(map[string][]*Subscription),
		updateChan:     make(chan component.Model),
		updateDoneChan: make(chan struct{}),
		errCh:          make(chan error),
		monitor:        monitor,
		grpcConfig:     grpcConfig,
		serverReady:    atomic.NewBool(false),
		doneChan:       make(chan struct{}),
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
func (m *Manager) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", m.listenAddr)
	if err != nil {
		return fmt.Errorf("error starting tcp listener for runtime manager: %w", err)
	}
	m.listenPort = listener.Addr().(*net.TCPAddr).Port

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(m.ca.Crt()); !ok {
		return errors.New("failed to append root CA")
	}
	creds := credentials.NewTLS(&tls.Config{
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      certPool,
		GetCertificate: m.getCertificate,
		MinVersion:     tls.VersionTLS12,
	})

	var server *grpc.Server
	if m.tracer != nil {
		apmInterceptor := apmgrpc.NewUnaryServerInterceptor(apmgrpc.WithRecovery(), apmgrpc.WithTracer(m.tracer))
		server = grpc.NewServer(
			grpc.UnaryInterceptor(apmInterceptor),
			grpc.Creds(creds),
			grpc.MaxRecvMsgSize(m.grpcConfig.MaxMsgSize),
		)
	} else {
		server = grpc.NewServer(
			grpc.Creds(creds),
			grpc.MaxRecvMsgSize(m.grpcConfig.MaxMsgSize),
		)
	}
	proto.RegisterElasticAgentServer(server, m)

	// start serving GRPC connections
	var wgServer sync.WaitGroup
	wgServer.Add(1)
	go func() {
		defer wgServer.Done()
		go m.serverLoop(ctx, listener, server)
	}()

	// Start the run loop, which continues on the main goroutine
	// until the context is canceled.
	m.runLoop(ctx)

	// Notify components to shutdown and wait for their response
	m.shutdown()

	// Close the rpc listener and wait for serverLoop to return
	listener.Close()
	wgServer.Wait()

	// Cancel any remaining connections
	server.Stop()
	return ctx.Err()
}

// The main run loop for the runtime manager, whose responsibilities are:
//   - Accept component model updates from the Coordinator
//   - Apply those updates safely without ever blocking, because a block here
//     propagates to a block in the Coordinator
//   - Close doneChan when the loop ends, so the Coordinator knows not to send
//     any more updates
func (m *Manager) runLoop(ctx context.Context) {
LOOP:
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			break LOOP
		case model := <-m.updateChan:
			// We got a new component model from m.Update(), mark it as the
			// next update to apply, overwriting any previous pending value.
			m.nextUpdate = &model
		case <-m.updateDoneChan:
			// An update call has finished, we can initiate another when available.
			m.updateInProgress = false
		}

		// After each select call, check if there's a pending update that
		// can be applied.
		if m.nextUpdate != nil && !m.updateInProgress {
			// There is a component model update available, apply it.
			go func(model component.Model) {
				// Run the update with tearDown set to true since this is coming
				// from a user-initiated policy update
				result := m.update(model, true)

				// When update is done, send its result back to the coordinator,
				// unless we're shutting down.
				select {
				case m.errCh <- result:
				case <-ctx.Done():
				}
				// Signal the runtime manager that we're finished. Note that
				// we don't select on ctx.Done() in this case because the runtime
				// manager always reads the results of an update once initiated,
				// even if it is shutting down.
				m.updateDoneChan <- struct{}{}
			}(*m.nextUpdate)
			m.updateInProgress = true
			m.nextUpdate = nil
		}
	}
	// Signal that the run loop is ended to unblock any incoming messages.
	// We need to do this before waiting on the final update result, otherwise
	// it might be stuck trying to send the result to errCh.
	close(m.doneChan)

	if m.updateInProgress {
		// Wait for the existing update to finish before shutting down,
		// otherwise the new update call closing everything will
		// conflict.
		<-m.updateDoneChan
		m.updateInProgress = false
	}
}

func (m *Manager) serverLoop(ctx context.Context, listener net.Listener, server *grpc.Server) {
	m.serverReady.Store(true)
	for ctx.Err() == nil {
		err := server.Serve(listener)
		if err != nil && ctx.Err() == nil {
			// Only log an error if we aren't shutting down, otherwise we'll spam
			// the logs with "use of closed network connection" for a connection that
			// was closed on purpose.
			m.logger.Errorf("control protocol listener failed: %s", err)
		}
	}
}

// Errors returns channel that errors are reported on.
func (m *Manager) Errors() <-chan error {
	return m.errCh
}

// Update forwards a new component model to Manager's run loop.
// When it has been processed, a result will be sent on Manager's
// error channel.
// Called from the main Coordinator goroutine.
//
// If calling from a test, you should read from errCh afterwards to avoid
// blocking Manager's main loop.
func (m *Manager) Update(model component.Model) {
	select {
	case m.updateChan <- model:
	case <-m.doneChan:
		// Manager is shutting down, ignore the update
	}
}

// PerformAction executes an action on a unit.
func (m *Manager) PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	paramBytes := []byte("{}")
	if params != nil {
		paramBytes, err = json.Marshal(params)
		if err != nil {
			return nil, err
		}
	}
	runtime := m.getRuntimeFromUnit(comp, unit)
	if runtime == nil {
		return nil, ErrNoUnit
	}

	req := &proto.ActionRequest{
		Id:       id.String(),
		Name:     name,
		Params:   paramBytes,
		UnitId:   unit.ID,
		UnitType: proto.UnitType(unit.Type),
		Type:     proto.ActionRequest_CUSTOM,
	}

	res, err := runtime.performAction(ctx, req)
	if err != nil {
		return nil, err
	}

	var respBody map[string]interface{}
	if res.Status == proto.ActionResponse_FAILED {
		if res.Result != nil {
			err = json.Unmarshal(res.Result, &respBody)
			if err != nil {
				return nil, err
			}
			errMsgT, ok := respBody["error"]
			if ok {
				errMsg, ok := errMsgT.(string)
				if ok {
					return nil, errors.New(errMsg)
				}
			}
		}
		return nil, errors.New("generic action failure")
	}
	if res.Result != nil {
		err = json.Unmarshal(res.Result, &respBody)
		if err != nil {
			return nil, err
		}
	}
	return respBody, nil
}

// PerformComponentDiagnostics executes the diagnostic action for the given components. If no components are provided then
// it performs diagnostics for all running components.
func (m *Manager) PerformComponentDiagnostics(ctx context.Context, additionalMetrics []cproto.AdditionalDiagnosticRequest, req ...component.Component) ([]ComponentDiagnostic, error) {
	if len(req) == 0 {
		if len(req) == 0 {
			m.currentMx.RLock()
			for _, runtime := range m.current {
				currComp := runtime.getCurrent()
				req = append(req, currComp)
			}
			m.currentMx.RUnlock()
		}
	}

	resp := []ComponentDiagnostic{}

	diagnosticCount := len(req)
	respChan := make(chan ComponentDiagnostic, diagnosticCount)
	for diag := 0; diag < diagnosticCount; diag++ {
		// transform the additional metrics field into JSON params
		params := client.DiagnosticParams{}
		if len(additionalMetrics) > 0 {
			for _, param := range additionalMetrics {
				params.AdditionalMetrics = append(params.AdditionalMetrics, param.String())
			}
		}
		// perform diagnostics in parallel; if we have a CPU pprof request, it'll take 30 seconds each.
		go func(iter int) {
			diagResponse, err := m.performDiagAction(ctx, req[iter], component.Unit{}, proto.ActionRequest_COMPONENT, params)
			respStruct := ComponentDiagnostic{
				Component: req[iter],
				Err:       err,
				Results:   diagResponse,
			}
			respChan <- respStruct

		}(diag)
	}

	// performDiagAction will have timeouts at various points,
	// but for the sake of paranoia, create our own timeout
	collectTimeout, cancel := context.WithTimeout(ctx, time.Minute*2)
	defer cancel()

	for res := 0; res < diagnosticCount; res++ {
		select {
		case <-collectTimeout.Done():
			return nil, fmt.Errorf("got context done waiting for diagnostics")
		case data := <-respChan:
			resp = append(resp, data)
		}
	}

	return resp, nil

}

// PerformDiagnostics executes the diagnostic action for the provided units. If no units are provided then
// it performs diagnostics for all current units.
func (m *Manager) PerformDiagnostics(ctx context.Context, req ...ComponentUnitDiagnosticRequest) []ComponentUnitDiagnostic {
	// build results from units
	var results []ComponentUnitDiagnostic
	if len(req) > 0 {
		for _, q := range req {
			r := m.getRuntimeFromUnit(q.Component, q.Unit)
			if r == nil {
				results = append(results, ComponentUnitDiagnostic{
					Unit: q.Unit,
					Err:  ErrNoUnit,
				})
			} else {
				results = append(results, ComponentUnitDiagnostic{
					Component: r.getCurrent(),
					Unit:      q.Unit,
				})
			}
		}
	} else {
		m.currentMx.RLock()
		for _, r := range m.current {
			currComp := r.getCurrent()
			for _, u := range currComp.Units {
				var err error
				if currComp.Err != nil {
					err = currComp.Err
				} else if u.Err != nil {
					err = u.Err
				}
				if err != nil {
					results = append(results, ComponentUnitDiagnostic{
						Component: currComp,
						Unit:      u,
						Err:       err,
					})
				} else {
					results = append(results, ComponentUnitDiagnostic{
						Component: currComp,
						Unit:      u,
					})
				}
			}
		}
		m.currentMx.RUnlock()
	}

	for i, r := range results {
		if r.Err != nil {
			// already in error don't perform diagnostics
			continue
		}

		diag, err := m.performDiagAction(ctx, r.Component, r.Unit, proto.ActionRequest_UNIT, client.DiagnosticParams{})
		if err != nil {
			r.Err = err
		} else {
			r.Results = diag
		}
		results[i] = r
	}
	return results
}

// Subscribe to changes in a component.
//
// Allows a component without that ID to exist. Once a component starts matching that ID then changes will start to
// be provided over the channel. Cancelling the context results in the subscription being unsubscribed.
//
// Note: Not reading from a subscription channel will cause the Manager to block.
func (m *Manager) Subscribe(ctx context.Context, componentID string) *Subscription {
	sub := newSubscription(ctx)

	// add latestState to channel
	m.currentMx.RLock()
	comp, ok := m.current[componentID]
	m.currentMx.RUnlock()
	if ok {
		latestState := comp.getLatest()
		go func() {
			select {
			case <-ctx.Done():
			case sub.ch <- latestState:
			}
		}()
	}

	// add subscription for future changes
	m.subMx.Lock()
	m.subscriptions[componentID] = append(m.subscriptions[componentID], sub)
	m.subMx.Unlock()

	go func() {
		<-ctx.Done()

		// unsubscribe
		m.subMx.Lock()
		defer m.subMx.Unlock()
		for key, subs := range m.subscriptions {
			for i, s := range subs {
				if sub == s {
					m.subscriptions[key] = append(m.subscriptions[key][:i], m.subscriptions[key][i+1:]...)
					return
				}
			}
		}
	}()

	return sub
}

// SubscribeAll subscribes to all changes in all components.
//
// This provides the current state for existing components at the time of first subscription. Cancelling the context
// results in the subscription being unsubscribed.
//
// Note: Not reading from a subscription channel will cause the Manager to block.
func (m *Manager) SubscribeAll(ctx context.Context) *SubscriptionAll {
	sub := newSubscriptionAll(ctx)

	// add the latest states
	m.currentMx.RLock()
	latest := make([]ComponentComponentState, 0, len(m.current))
	for _, comp := range m.current {
		latest = append(latest, ComponentComponentState{Component: comp.getCurrent(), State: comp.getLatest()})
	}
	m.currentMx.RUnlock()
	if len(latest) > 0 {
		go func() {
			for _, l := range latest {
				select {
				case <-ctx.Done():
					return
				case sub.ch <- l:
				}
			}
		}()
	}

	// add subscription for future changes
	m.subAllMx.Lock()
	m.subscribeAll = append(m.subscribeAll, sub)
	m.subAllMx.Unlock()

	go func() {
		<-ctx.Done()

		// unsubscribe
		m.subAllMx.Lock()
		defer m.subAllMx.Unlock()
		for i, s := range m.subscribeAll {
			if sub == s {
				m.subscribeAll = append(m.subscribeAll[:i], m.subscribeAll[i+1:]...)
				return
			}
		}
	}()

	return sub
}

// Checkin is called by v1 sub-processes and has been removed.
func (m *Manager) Checkin(_ proto.ElasticAgent_CheckinServer) error {
	return status.Error(codes.Unavailable, "removed; upgrade to V2")
}

// CheckinV2 is the new v2 communication for components.
func (m *Manager) CheckinV2(server proto.ElasticAgent_CheckinV2Server) error {
	initCheckinChan := make(chan *proto.CheckinObserved)
	go func() {
		// this goroutine will not be leaked, because when the main function
		// returns it will close the connection. that will cause this
		// function to return.
		observed, err := server.Recv()
		if err != nil {
			close(initCheckinChan)
			return
		}
		initCheckinChan <- observed
	}()

	var ok bool
	var initCheckin *proto.CheckinObserved

	t := time.NewTimer(initialCheckinTimeout)
	select {
	case initCheckin, ok = <-initCheckinChan:
		t.Stop()
	case <-t.C:
		// close connection
		return status.Error(codes.DeadlineExceeded, "never sent initial observed message")
	}
	if !ok {
		// close connection
		return nil
	}

	runtime := m.getRuntimeFromToken(initCheckin.Token)
	if runtime == nil {
		// no component runtime with token; close connection
		return status.Error(codes.PermissionDenied, "invalid token")
	}

	return runtime.comm.checkin(server, initCheckin)
}

// Actions is the actions stream used to broker actions between Elastic Agent and components.
func (m *Manager) Actions(server proto.ElasticAgent_ActionsServer) error {
	initRespChan := make(chan *proto.ActionResponse)
	go func() {
		// go func will not be leaked, because when the main function
		// returns it will close the connection. that will cause this
		// function to return.
		observed, err := server.Recv()
		if err != nil {
			close(initRespChan)
			return
		}
		initRespChan <- observed
	}()

	var ok bool
	var initResp *proto.ActionResponse

	t := time.NewTimer(initialCheckinTimeout)
	select {
	case initResp, ok = <-initRespChan:
		t.Stop()
	case <-t.C:
		// close connection
		m.logger.Debug("actions stream never sent initial response message; closing connection")
		return status.Error(codes.DeadlineExceeded, "never sent initial response message")
	}
	if !ok {
		// close connection
		return nil
	}
	if initResp.Id != client.ActionResponseInitID {
		// close connection
		m.logger.Debug("actions stream first response message must be an init message; closing connection")
		return status.Error(codes.InvalidArgument, "initial response must be an init message")
	}

	runtime := m.getRuntimeFromToken(initResp.Token)
	if runtime == nil {
		// no component runtime with token; close connection
		m.logger.Debug("actions stream sent an invalid token; closing connection")
		return status.Error(codes.PermissionDenied, "invalid token")
	}

	return runtime.comm.actions(server)
}

// update updates the current state of the running components.
// It is only called by the main runtime manager goroutine in Manager.Run.
//
// This returns as soon as possible, work is performed in the background.
func (m *Manager) update(model component.Model, teardown bool) error {
	// prepare the components to add consistent shipper connection information between
	// the connected components in the model
	err := m.connectShippers(model.Components)
	if err != nil {
		return err
	}

	touched := make(map[string]bool)
	newComponents := make([]component.Component, 0, len(model.Components))
	for _, comp := range model.Components {
		touched[comp.ID] = true
		m.currentMx.RLock()
		existing, ok := m.current[comp.ID]
		m.currentMx.RUnlock()
		if ok {
			// existing component; send runtime updated value
			existing.setCurrent(comp)
			if err := existing.runtime.Update(comp); err != nil {
				return fmt.Errorf("failed to update component %s: %w", comp.ID, err)
			}
			continue
		}
		newComponents = append(newComponents, comp)
	}

	var stop []*componentRuntimeState
	m.currentMx.RLock()
	for id, existing := range m.current {
		// skip if already touched (meaning it still existing)
		if _, done := touched[id]; done {
			continue
		}
		// component was removed (time to clean it up)
		stop = append(stop, existing)
	}
	m.currentMx.RUnlock()
	if len(stop) > 0 {
		var stoppedWg sync.WaitGroup
		stoppedWg.Add(len(stop))
		for _, existing := range stop {
			m.logger.Debugf("Stopping component %q", existing.id)
			_ = existing.stop(teardown, model.Signed)
			// stop is async, wait for operation to finish,
			// otherwise new instance may be started and components
			// may fight for resources (e.g ports, files, locks)
			go func(state *componentRuntimeState) {
				m.waitForStopped(state)
				stoppedWg.Done()
			}(existing)
		}
		stoppedWg.Wait()
	}

	// start all not started
	for _, comp := range newComponents {
		// new component; create its runtime
		logger := m.baseLogger.Named(fmt.Sprintf("component.runtime.%s", comp.ID))
		state, err := newComponentRuntimeState(m, logger, m.monitor, comp)
		if err != nil {
			return fmt.Errorf("failed to create new component %s: %w", comp.ID, err)
		}
		m.currentMx.Lock()
		m.current[comp.ID] = state
		m.currentMx.Unlock()
		if err = state.start(); err != nil {
			return fmt.Errorf("failed to start component %s: %w", comp.ID, err)
		}
	}

	return nil
}

func (m *Manager) waitForStopped(comp *componentRuntimeState) {
	if comp == nil {
		return
	}
	currComp := comp.getCurrent()
	compID := currComp.ID
	timeout := defaultStopTimeout
	if currComp.InputSpec != nil &&
		currComp.InputSpec.Spec.Service != nil &&
		currComp.InputSpec.Spec.Service.Operations.Uninstall != nil &&
		currComp.InputSpec.Spec.Service.Operations.Uninstall.Timeout > 0 {
		// if component is a service and timeout is defined, use the one defined
		timeout = currComp.InputSpec.Spec.Service.Operations.Uninstall.Timeout
	}

	timeoutCh := time.After(timeout)
	for {
		latestState := comp.getLatest()
		if latestState.State == client.UnitStateStopped {
			m.logger.Debugf("component %q stopped.", compID)
			return
		}

		m.currentMx.RLock()
		if _, exists := m.current[compID]; !exists {
			m.currentMx.RUnlock()
			return
		}
		m.currentMx.RUnlock()

		select {
		case <-timeoutCh:
			m.logger.Errorf("timeout exceeded waiting for component %q to stop", compID)
			return
		case <-time.After(stopCheckRetryPeriod):
		}
	}
}

// Called from Manager's Run goroutine.
func (m *Manager) shutdown() {
	// don't tear down as this is just a shutdown, so components most likely will come back
	// on next start of the manager
	_ = m.update(component.Model{Components: []component.Component{}}, false)

	// wait until all components are removed
	for {
		m.currentMx.RLock()
		length := len(m.current)
		m.currentMx.RUnlock()
		if length <= 0 {
			return
		}
		<-time.After(100 * time.Millisecond)
	}
}

// stateChanged notifies of the state change and returns true if the state is final (stopped)
func (m *Manager) stateChanged(state *componentRuntimeState, latest ComponentState) (exit bool) {
	m.subAllMx.RLock()
	for _, sub := range m.subscribeAll {
		select {
		case <-sub.ctx.Done():
		case sub.ch <- ComponentComponentState{
			Component: state.getCurrent(),
			State:     latest,
		}:
		}
	}
	m.subAllMx.RUnlock()

	m.subMx.RLock()
	subs := m.subscriptions[state.id]
	for _, sub := range subs {
		select {
		case <-sub.ctx.Done():
		case sub.ch <- latest:
		}
	}
	m.subMx.RUnlock()

	shutdown := state.shuttingDown.Load()
	if shutdown && latest.State == client.UnitStateStopped {
		// shutdown is complete; remove from currComp
		m.currentMx.Lock()
		delete(m.current, state.id)
		m.currentMx.Unlock()

		exit = true
	}
	return exit
}

func (m *Manager) getCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var cert *tls.Certificate

	m.currentMx.RLock()
	for _, runtime := range m.current {
		if runtime.comm.name == chi.ServerName {
			cert = runtime.comm.cert.Certificate
			break
		}
	}
	m.currentMx.RUnlock()
	if cert != nil {
		return cert, nil
	}

	return nil, errors.New("no supported TLS certificate")
}

// Called from GRPC listeners
func (m *Manager) getRuntimeFromToken(token string) *componentRuntimeState {
	m.currentMx.RLock()
	defer m.currentMx.RUnlock()

	for _, runtime := range m.current {
		if runtime.comm.token == token {
			return runtime
		}
	}
	return nil
}

func (m *Manager) getRuntimeFromUnit(comp component.Component, unit component.Unit) *componentRuntimeState {
	m.currentMx.RLock()
	defer m.currentMx.RUnlock()
	for _, c := range m.current {
		if c.id == comp.ID {
			currComp := c.getCurrent()
			for _, u := range currComp.Units {
				if u.Type == unit.Type && u.ID == unit.ID {
					return c
				}
			}
		}
	}
	return nil
}

func (m *Manager) getRuntimeFromComponent(comp component.Component) *componentRuntimeState {
	m.currentMx.RLock()
	defer m.currentMx.RUnlock()
	for _, currentComp := range m.current {
		if currentComp.id == comp.ID {
			return currentComp
		}
	}
	return nil
}

func (m *Manager) getListenAddr() string {
	addr := strings.SplitN(m.listenAddr, ":", 2)
	if len(addr) == 2 && addr[1] == "0" {
		return fmt.Sprintf("%s:%d", addr[0], m.listenPort)
	}
	return m.listenAddr
}

// performDiagAction creates a diagnostic ActionRequest and executes it against the runtime that's mapped to the specified component.
// if the specified actionLevel is ActionRequest_COMPONENT, the unit field is ignored.
func (m *Manager) performDiagAction(ctx context.Context, comp component.Component, unit component.Unit, actionLevel proto.ActionRequest_Level, params client.DiagnosticParams) ([]*proto.ActionDiagnosticUnitResult, error) {
	ctx, cancel := context.WithTimeout(ctx, diagnosticTimeout)
	defer cancel()

	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	var runtime *componentRuntimeState
	if actionLevel == proto.ActionRequest_UNIT {
		runtime = m.getRuntimeFromUnit(comp, unit)
		if runtime == nil {
			return nil, ErrNoUnit
		}
	} else {
		runtime = m.getRuntimeFromComponent(comp)
		if runtime == nil {
			return nil, ErrNoComponent
		}
	}

	if len(params.AdditionalMetrics) > 0 {
		m.logger.Debugf("Performing diagnostic action with params: %v", params.AdditionalMetrics)
	}
	marshalParams, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("error marshalling json for params: %w", err)
	}

	req := &proto.ActionRequest{
		Id:     id.String(),
		Type:   proto.ActionRequest_DIAGNOSTICS,
		Level:  actionLevel,
		Params: marshalParams,
	}

	if actionLevel == proto.ActionRequest_UNIT {
		req.UnitId = unit.ID
		req.UnitType = proto.UnitType(unit.Type)
	}

	res, err := runtime.performAction(ctx, req)
	// the only way this can return an error is a context Done(), be sure to make that explicit.
	if err != nil {
		if errors.Is(context.DeadlineExceeded, err) {
			return nil, fmt.Errorf("diagnostic action timed out, deadline is %s: %w", diagnosticTimeout, err)
		}
		return nil, fmt.Errorf("error running performAction: %w", err)
	}
	if res.Status == proto.ActionResponse_FAILED {
		var respBody map[string]interface{}
		if res.Result != nil {
			err = json.Unmarshal(res.Result, &respBody)
			if err != nil {
				return nil, fmt.Errorf("error unmarshaling JSON in FAILED response: %w", err)
			}
			errMsgT, ok := respBody["error"]
			if ok {
				errMsg, ok := errMsgT.(string)
				if ok {
					return nil, errors.New(errMsg)
				}
			}
		}
		return nil, errors.New("unit failed to perform diagnostics, no error could be extracted from response")
	}
	return res.Diagnostic, nil
}
