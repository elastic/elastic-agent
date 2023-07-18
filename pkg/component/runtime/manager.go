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
	diagnosticTimeout = 20 * time.Second

	// stopCheckRetryPeriod is a idle time between checks for component stopped state
	stopCheckRetryPeriod = 200 * time.Millisecond
)

var (
	// ErrNoUnit returned when manager is not controlling this unit.
	ErrNoUnit = errors.New("no unit under control of this manager")
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

// Manager for the entire runtime of operating components.
type Manager struct {
	proto.UnimplementedElasticAgentServer

	logger     *logger.Logger
	baseLogger *logger.Logger
	ca         *authority.CertificateAuthority
	listenAddr string
	agentInfo  *info.AgentInfo
	tracer     *apm.Tracer
	monitor    MonitoringManager
	grpcConfig *configuration.GRPCConfig

	// netMx synchronizes the access to listener and server only
	netMx    sync.RWMutex
	listener net.Listener
	server   *grpc.Server

	// waitMx synchronizes the access to waitReady only
	waitMx    sync.RWMutex
	waitReady map[string]waitForReady

	// updateMx protects the call to update to ensure that
	// only one call to update occurs at a time
	updateMx sync.Mutex

	// currentMx protects access to the current map only
	currentMx sync.RWMutex
	current   map[string]*componentRuntimeState

	shipperConns map[string]*shipperConn

	//subMx            sync.RWMutex
	//subscriptions    map[string][]*Subscription
	stateChangeChan chan ComponentComponentState
	updateChan      chan updateRequest
	errorChan       chan error
	//subAllMx      sync.RWMutex
	//subscribeAll  []*SubscriptionAll

	//errCh chan error

	// upon creation the Manager is neither running not shutting down, thus both
	// flags are needed.
	running      atomic.Bool
	shuttingDown atomic.Bool
}

type updateRequest struct {
	components []component.Component
	tearDown   bool
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
		logger:       logger,
		baseLogger:   baseLogger,
		ca:           ca,
		listenAddr:   listenAddr,
		agentInfo:    agentInfo,
		tracer:       tracer,
		waitReady:    make(map[string]waitForReady),
		current:      make(map[string]*componentRuntimeState),
		shipperConns: make(map[string]*shipperConn),
		//subscriptions: make(map[string][]*Subscription),
		stateChangeChan: make(chan ComponentComponentState),
		updateChan:      make(chan updateRequest),
		errorChan:       make(chan error),
		monitor:         monitor,
		grpcConfig:      grpcConfig,
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
	m.running.Store(true)
	m.shuttingDown.Store(false)

	lis, err := net.Listen("tcp", m.listenAddr)
	if err != nil {
		return fmt.Errorf("error starting tcp listener for runtime manager: %w", err)
	}
	m.netMx.Lock()
	m.listener = lis
	m.netMx.Unlock()

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
	m.netMx.Lock()
	m.server = server
	m.netMx.Unlock()
	proto.RegisterElasticAgentServer(m.server, m)

	// start serving GRPC connections
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			err := server.Serve(lis)
			if err != nil {
				m.logger.Errorf("control protocol failed: %s", err)
			}
			if ctx.Err() != nil {
				// context has an error don't start again
				return
			}
		}
	}()

	// updateErrChan is a local placeholder that holds m.errorChan when
	// we have a result to send from an update call and nil otherwise.
	var updateErrChan chan error
	var updateErr error
	for ctx.Err() == nil {

		select {
		case <-ctx.Done():
		case req := <-m.updateChan:
			// Begin the update, and point updateErrChan at our error reporting
			// channel so we can notify Coordinator of the result.
			updateErr = m.update(req.components, req.tearDown)
			updateErrChan = m.errorChan
		case updateErrChan <- updateErr:
			// We sent the most recent update result, clear the channel until the
			// next update
			updateErrChan = nil
		}
	}
	m.running.Store(false)
	m.shuttingDown.Store(true)
	m.shutdown()

	server.Stop()
	wg.Wait()
	m.netMx.Lock()
	m.listener = nil
	m.server = nil
	m.netMx.Unlock()
	return ctx.Err()
}

// Errors returns channel that errors are reported on.
func (m *Manager) Errors() <-chan error {
	return m.errorChan
}

// Update updates the currComp state of the running components.
// Called from the main Coordinator goroutine.
//
// This returns as soon as possible, the work is performed in the background.
func (m *Manager) Update(components []component.Component) error {
	shuttingDown := m.shuttingDown.Load()
	if shuttingDown {
		// ignore any updates once shutdown started
		return nil
	}
	// teardown is true because the public `Update` method would be coming directly from
	// policy so if a component was removed it needs to be torn down.
	m.updateChan <- updateRequest{components, true}
	return nil
}

// State returns the current component states.
func (m *Manager) State() []ComponentComponentState {
	m.currentMx.RLock()
	defer m.currentMx.RUnlock()
	states := make([]ComponentComponentState, 0, len(m.current))
	for _, crs := range m.current {
		crs.latestMx.RLock()
		var legacyPID string
		if crs.runtime != nil {
			if commandRuntime, ok := crs.runtime.(*commandRuntime); ok {
				if commandRuntime != nil {
					procInfo := commandRuntime.proc
					if procInfo != nil {
						legacyPID = fmt.Sprint(commandRuntime.proc.PID)
					}
				}
			}
		}
		states = append(states, ComponentComponentState{
			Component: crs.getCurrent(),
			State:     crs.latestState.Copy(),
			LegacyPID: legacyPID,
		})
		crs.latestMx.RUnlock()
	}
	return states
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
		diag, err := m.performDiagAction(ctx, r.Component, r.Unit)
		if err != nil {
			r.Err = err
		} else {
			r.Results = diag
		}
		results[i] = r
	}
	return results
}

func (m *Manager) StateChangeChan() <-chan ComponentComponentState {
	return m.stateChangeChan
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
		m.logger.Debug("check-in stream never sent initial observed message; closing connection")
		return status.Error(codes.DeadlineExceeded, "never sent initial observed message")
	}
	if !ok {
		// close connection
		return nil
	}

	runtime := m.getRuntimeFromToken(initCheckin.Token)
	if runtime == nil {
		// no component runtime with token; close connection
		m.logger.Debug("check-in stream sent an invalid token; closing connection")
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
//
// This returns as soon as possible, work is performed in the background.
func (m *Manager) update(components []component.Component, teardown bool) error {
	// ensure that only one `update` can occur at the same time
	m.updateMx.Lock()
	defer m.updateMx.Unlock()

	// prepare the components to add consistent shipper connection information between
	// the connected components in the model
	err := m.connectShippers(components)
	if err != nil {
		return err
	}

	touched := make(map[string]bool)
	newComponents := make([]component.Component, 0, len(components))
	for _, comp := range components {
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
			_ = existing.stop(teardown)
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
		comp.latestMx.RLock()
		latestState := comp.latestState
		comp.latestMx.RUnlock()
		if latestState.State == client.UnitStateStopped {
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
			return
		case <-time.After(stopCheckRetryPeriod):
		}
	}
}

// Called from Manager's Run goroutine.
func (m *Manager) shutdown() {
	// don't tear down as this is just a shutdown, so components most likely will come back
	// on next start of the manager
	_ = m.update([]component.Component{}, false)

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

	// TODO: select on this with overall Manager channel
	m.stateChangeChan <- ComponentComponentState{
		Component: state.getCurrent(),
		State:     latest,
	}

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

	m.waitMx.RLock()
	for _, waiter := range m.waitReady {
		if waiter.name == chi.ServerName {
			cert = waiter.cert.Certificate
			break
		}
	}
	m.waitMx.RUnlock()
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

func (m *Manager) getListenAddr() string {
	addr := strings.SplitN(m.listenAddr, ":", 2)
	if len(addr) == 2 && addr[1] == "0" {
		m.netMx.RLock()
		lis := m.listener
		m.netMx.RUnlock()
		if lis != nil {
			port := lis.Addr().(*net.TCPAddr).Port
			return fmt.Sprintf("%s:%d", addr[0], port)
		}
	}
	return m.listenAddr
}

func (m *Manager) performDiagAction(ctx context.Context, comp component.Component, unit component.Unit) ([]*proto.ActionDiagnosticUnitResult, error) {
	ctx, cancel := context.WithTimeout(ctx, diagnosticTimeout)
	defer cancel()

	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	runtime := m.getRuntimeFromUnit(comp, unit)
	if runtime == nil {
		return nil, ErrNoUnit
	}

	req := &proto.ActionRequest{
		Id:       id.String(),
		UnitId:   unit.ID,
		UnitType: proto.UnitType(unit.Type),
		Type:     proto.ActionRequest_DIAGNOSTICS,
	}
	res, err := runtime.performAction(ctx, req)
	if err != nil {
		return nil, err
	}
	if res.Status == proto.ActionResponse_FAILED {
		var respBody map[string]interface{}
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
		return nil, errors.New("unit failed to perform diagnostics, no error could be extracted from response")
	}
	return res.Diagnostic, nil
}

type waitForReady struct {
	name string
	cert *authority.Pair
}

// waitForReady waits until the manager is ready to be used.
// Used for testing.
//
// This verifies that the GRPC server is up and running.
func (m *Manager) waitForReady(ctx context.Context) error {
	tk, err := uuid.NewV4()
	if err != nil {
		return err
	}
	token := tk.String()
	name, err := genServerName()
	if err != nil {
		return err
	}
	pair, err := m.ca.GeneratePairWithName(name)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(pair.Crt, pair.Key)
	if err != nil {
		return err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(m.ca.Crt())
	trans := credentials.NewTLS(&tls.Config{
		ServerName:   name,
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	})

	m.waitMx.Lock()
	m.waitReady[token] = waitForReady{
		name: name,
		cert: pair,
	}
	m.waitMx.Unlock()

	defer func() {
		m.waitMx.Lock()
		delete(m.waitReady, token)
		m.waitMx.Unlock()
	}()

	for {
		m.netMx.RLock()
		lis := m.listener
		srv := m.server
		m.netMx.RUnlock()
		if lis != nil && srv != nil {
			addr := m.getListenAddr()
			c, err := grpc.Dial(addr, grpc.WithTransportCredentials(trans))
			if err == nil {
				_ = c.Close()
				return nil
			}
		}

		t := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}
