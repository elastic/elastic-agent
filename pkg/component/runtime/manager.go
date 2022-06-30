package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofrs/uuid"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/atomic"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

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
)

var (
	// ErrNoUnit returned when manager is not controlling this unit.
	ErrNoUnit = errors.New("no unit under control of this manager")
)

// Manager for the entire runtime of operating components.
type Manager struct {
	proto.UnimplementedElasticAgentServer

	logger     *logger.Logger
	ca         *authority.CertificateAuthority
	listenAddr string
	tracer     *apm.Tracer

	netMx    sync.RWMutex
	listener net.Listener
	server   *grpc.Server

	waitMx    sync.RWMutex
	waitReady map[string]waitForReady

	mx      sync.RWMutex
	current map[string]*componentRuntimeState

	subMx         sync.RWMutex
	subscriptions map[string][]*Subscription

	shuttingDown atomic.Bool
}

// NewManager creates a new manager.
func NewManager(logger *logger.Logger, listenAddr string, tracer *apm.Tracer) (*Manager, error) {
	ca, err := authority.NewCA()
	if err != nil {
		return nil, err
	}
	m := &Manager{
		logger:        logger,
		ca:            ca,
		listenAddr:    listenAddr,
		tracer:        tracer,
		waitReady:     make(map[string]waitForReady),
		current:       make(map[string]*componentRuntimeState),
		subscriptions: make(map[string][]*Subscription),
	}
	return m, nil
}

// Run runs the manager.
//
// Blocks until the context is done.
func (m *Manager) Run(ctx context.Context) error {
	lis, err := net.Listen("tcp", m.listenAddr)
	if err != nil {
		return err
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
		)
	} else {
		server = grpc.NewServer(grpc.Creds(creds))
	}
	m.netMx.Lock()
	m.server = server
	m.netMx.Unlock()
	proto.RegisterElasticAgentServer(m.server, m)
	m.shuttingDown.Store(false)

	// start serving GRPC connections
	errCh := make(chan error)
	go func() {
		errCh <- server.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		server.Stop()
		err = <-errCh
	case err = <-errCh:
	}
	m.shutdown()
	m.netMx.Lock()
	m.listener = nil
	m.server = nil
	m.netMx.Unlock()
	return err
}

// WaitForReady waits until the manager is ready to be used.
//
// This verifies that the GRPC server is up and running.
func (m *Manager) WaitForReady(ctx context.Context) error {
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

// Update updates the current state of the running components.
//
// This returns as soon as possible, work is performed in the background to
func (m *Manager) Update(components []component.Component) error {
	shuttingDown := m.shuttingDown.Load()
	if shuttingDown {
		// ignore any updates once shutdown started
		return nil
	}
	// teardown is true because the public `Update` method would be coming directly from
	// policy so if a component was removed it needs to be torn down.
	return m.update(components, true)
}

// PerformAction executes an action on a unit.
func (m *Manager) PerformAction(ctx context.Context, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error) {
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
	runtime := m.getRuntimeFromUnit(unit)
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

// Subscribe to changes in a component.
//
// Allows a component without that ID to exists. Once a component starts matching that ID then changes will start to
// be provided over the channel.
//
// Note: Not reading from a subscription channel will cause the Manager to block.
func (m *Manager) Subscribe(componentID string) *Subscription {
	sub := newSubscription(m)

	// add latest to channel
	m.mx.RLock()
	comp, ok := m.current[componentID]
	m.mx.RUnlock()
	if ok {
		comp.latestMx.RLock()
		sub.ch <- comp.latest
		comp.latestMx.RUnlock()
	}

	// add subscription for future changes
	m.subMx.Lock()
	m.subscriptions[componentID] = append(m.subscriptions[componentID], sub)
	defer m.subMx.Unlock()

	return sub
}

func (m *Manager) Checkin(_ proto.ElasticAgent_CheckinServer) error {
	return status.Error(codes.Unavailable, "removed; upgrade to V2")
}

func (m *Manager) CheckinV2(server proto.ElasticAgent_CheckinV2Server) error {
	initCheckinChan := make(chan *proto.CheckinObserved)
	go func() {
		// go func will not be leaked, because when the main function
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
// This returns as soon as possible, work is performed in the background to
func (m *Manager) update(components []component.Component, teardown bool) error {
	m.mx.Lock()
	defer m.mx.Unlock()

	touched := make(map[string]bool)
	for _, comp := range components {
		touched[comp.ID] = true
		existing, ok := m.current[comp.ID]
		if ok {
			// existing component; send runtime updated value
			existing.current = comp
			if err := existing.runtime.Update(comp); err != nil {
				return fmt.Errorf("failed to update component %s: %w", comp.ID, err)
			}
		} else {
			// new component; create its runtime
			logger := m.logger.Named(fmt.Sprintf("component.runtime.%s", comp.ID))
			state, err := newComponentRuntimeState(m, logger, comp)
			if err != nil {
				return fmt.Errorf("failed to create new component %s: %w", comp.ID, err)
			}
			m.current[comp.ID] = state
			err = state.start()
			if err != nil {
				return fmt.Errorf("failed to start component %s: %w", comp.ID, err)
			}
		}
	}
	for id, existing := range m.current {
		// skip if already touched (meaning it still existing)
		if _, done := touched[id]; done {
			continue
		}
		// component was removed (time to clean it up)
		existing.stop(teardown)
	}
	return nil
}

func (m *Manager) shutdown() {
	m.shuttingDown.Store(true)

	// don't tear down as this is just a shutdown, so components most likely will come back
	// on next start of the manager
	_ = m.update([]component.Component{}, false)

	// wait until all components are removed
	for {
		m.mx.Lock()
		length := len(m.current)
		m.mx.Unlock()
		if length <= 0 {
			return
		}
		<-time.After(100 * time.Millisecond)
	}
}

func (m *Manager) stateChanged(state *componentRuntimeState, latest ComponentState) {
	m.subMx.RLock()
	subs, ok := m.subscriptions[state.current.ID]
	if ok {
		for _, sub := range subs {
			sub.ch <- latest
		}
	}
	m.subMx.RUnlock()

	shutdown := state.shuttingDown.Load()
	if shutdown && latest.State == client.UnitStateStopped {
		// shutdown is complete; remove from current
		m.mx.Lock()
		delete(m.current, state.current.ID)
		m.mx.Unlock()

		state.destroy()
	}
}

func (m *Manager) unsubscribe(subscription *Subscription) {
	m.subMx.Lock()
	defer m.subMx.Unlock()
	for key, subs := range m.subscriptions {
		for i, sub := range subs {
			if subscription == sub {
				m.subscriptions[key] = append(m.subscriptions[key][:i], m.subscriptions[key][i+1:]...)
				return
			}
		}
	}
}

func (m *Manager) getCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var cert *tls.Certificate

	m.mx.RLock()
	for _, runtime := range m.current {
		if runtime.comm.name == chi.ServerName {
			cert = runtime.comm.cert.Certificate
			break
		}
	}
	m.mx.RUnlock()
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

func (m *Manager) getRuntimeFromToken(token string) *componentRuntimeState {
	m.mx.RLock()
	defer m.mx.RUnlock()

	for _, runtime := range m.current {
		if runtime.comm.token == token {
			return runtime
		}
	}
	return nil
}

func (m *Manager) getRuntimeFromUnit(unit component.Unit) *componentRuntimeState {
	m.mx.RLock()
	defer m.mx.RUnlock()
	for _, comp := range m.current {
		for _, u := range comp.current.Units {
			if u.Type == unit.Type && u.ID == unit.ID {
				return comp
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

type waitForReady struct {
	name string
	cert *authority.Pair
}
