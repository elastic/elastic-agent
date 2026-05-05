// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/server"
	"github.com/open-telemetry/opamp-go/server/types"
	otelstatus "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"

	"github.com/elastic/elastic-agent/internal/pkg/otel/status"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	// opampListenPath is the URL path on the manager's OpAMP server. This is
	// also opamp-go's default ListenPath; we set it explicitly for clarity.
	opampListenPath = "/v1/opamp"

	// opampWatchdogDuration matches the previous healthcheckv2 polling watchdog:
	// if no Health message is received within this window, the session emits a
	// RecoverableError("failed to connect to collector") status.
	opampWatchdogDuration = 130 * time.Second

	// failedToConnectErrMsg is the error message emitted by the watchdog. Kept
	// stable for compatibility with anything matching on the exact text.
	failedToConnectErrMsg = "failed to connect to collector"
)

// generateOpAMPSecret returns a random 32-byte hex-encoded shared secret. The
// secret is sent as the Bearer token in the Authorization header by the
// collector's opamp extension and validated by the OpAMP server.
func generateOpAMPSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating opamp secret: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// opampServer is an embedded OpAMP HTTP server that the supervised collector's
// opamp extension polls to upload its health.
//
// Lifetime is tied to the OTelManager (one server per manager, started in
// NewOTelManager). A single collectorSession at a time consumes incoming
// Health messages — the manager opens a session when starting a collector and
// closes it when stopping.
type opampServer struct {
	log    *logger.Logger
	secret string

	srv      server.OpAMPServer
	endpoint string

	mx      sync.Mutex
	session *opampSession
}

// newOpAMPServer constructs an OpAMP server with the given logger and secret.
// Call Start to bind it to a local port.
func newOpAMPServer(log *logger.Logger, secret string) *opampServer {
	s := &opampServer{
		log:    log,
		secret: secret,
	}
	s.srv = server.New(opampLoggerAdapter{log: log})
	return s
}

// Start binds the server to bindAddr (e.g. "127.0.0.1:0" for a random port).
// Returns an error if binding fails. The endpoint URL is available via
// Endpoint() after a successful Start.
func (s *opampServer) Start(bindAddr string) error {
	if bindAddr == "" {
		bindAddr = "127.0.0.1:0"
	}
	settings := server.StartSettings{
		ListenEndpoint: bindAddr,
		ListenPath:     opampListenPath,
		Settings: server.Settings{
			Callbacks: types.Callbacks{
				OnConnecting: s.onConnecting,
			},
		},
	}
	if err := s.srv.Start(settings); err != nil {
		return fmt.Errorf("starting opamp server on %s: %w", bindAddr, err)
	}
	addr := s.srv.Addr()
	if addr == nil {
		return errors.New("opamp server: nil Addr after Start")
	}
	s.endpoint = fmt.Sprintf("http://%s%s", addr.String(), opampListenPath)
	return nil
}

// Stop closes any active session and stops the underlying http server.
func (s *opampServer) Stop(ctx context.Context) error {
	s.CloseSession()
	if s.srv != nil {
		return s.srv.Stop(ctx)
	}
	return nil
}

// Endpoint returns the URL the opamp extension should use to reach the server,
// e.g. "http://127.0.0.1:1234/v1/opamp". Empty until Start succeeds.
func (s *opampServer) Endpoint() string {
	return s.endpoint
}

// StartSession begins a new collector session. Closes any prior session and
// returns the new one. statusFn receives translated status updates: an
// initial StatusStarting is emitted synchronously, then changes derived from
// incoming Health messages, plus watchdog/force-resend events.
func (s *opampServer) StartSession(ctx context.Context, statusFn func(context.Context, *otelstatus.AggregateStatus)) *opampSession {
	sess := &opampSession{
		log:      s.log,
		statusFn: statusFn,
		healthCh: make(chan *otelstatus.AggregateStatus, 1),
		forceCh:  make(chan struct{}, 1),
		closeCh:  make(chan struct{}),
		doneCh:   make(chan struct{}),
	}

	s.mx.Lock()
	prev := s.session
	s.session = sess
	s.mx.Unlock()

	if prev != nil {
		// Defensive: manager should close before opening a new session.
		s.log.Warn("opamp server: closing prior session that was still active")
		prev.close()
	}

	go sess.run(ctx)
	return sess
}

// CloseSession terminates the active session, if any. Safe to call multiple
// times. Blocks until the session goroutine exits.
func (s *opampServer) CloseSession() {
	s.mx.Lock()
	sess := s.session
	s.session = nil
	s.mx.Unlock()
	if sess != nil {
		sess.close()
	}
}

// onConnecting is called once per HTTP request. We validate the shared secret
// here so unauthenticated requests are rejected before the OpAMP message
// loop runs.
func (s *opampServer) onConnecting(req *http.Request) types.ConnectionResponse {
	if !s.checkAuth(req) {
		return types.ConnectionResponse{
			Accept:         false,
			HTTPStatusCode: http.StatusUnauthorized,
		}
	}
	return types.ConnectionResponse{
		Accept: true,
		ConnectionCallbacks: types.ConnectionCallbacks{
			OnMessage: s.onMessage,
		},
	}
}

func (s *opampServer) checkAuth(req *http.Request) bool {
	got := req.Header.Get(opampAuthorizationHeader)
	want := "Bearer " + s.secret
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// onMessage forwards Health messages from the collector to the active session.
// Messages received without an active session are dropped.
func (s *opampServer) onMessage(ctx context.Context, _ types.Connection, msg *protobufs.AgentToServer) *protobufs.ServerToAgent {
	if msg != nil && msg.Health != nil {
		s.mx.Lock()
		sess := s.session
		s.mx.Unlock()
		if sess != nil {
			sess.deliverHealth(componentHealthToAggregate(msg.Health))
		}
	}
	// Return an empty response. We don't push remote configs, restart commands,
	// or other directives — the manager owns the collector lifecycle directly.
	var instanceUID []byte
	if msg != nil {
		instanceUID = msg.InstanceUid
	}
	return &protobufs.ServerToAgent{InstanceUid: instanceUID}
}

// opampSession encapsulates the per-collector status processing loop. It owns
// the watchdog timer, the lastStatus cache for force-resend, and dedup of
// repeated statuses.
type opampSession struct {
	log      *logger.Logger
	statusFn func(context.Context, *otelstatus.AggregateStatus)

	healthCh chan *otelstatus.AggregateStatus
	forceCh  chan struct{}
	closeCh  chan struct{}
	doneCh   chan struct{}

	// watchdogDuration is overridable for testing.
	watchdogDuration time.Duration
}

// deliverHealth pushes a translated status to the session goroutine,
// latest-wins. Drops if closed.
func (s *opampSession) deliverHealth(st *otelstatus.AggregateStatus) {
	select {
	case <-s.healthCh:
	default:
	}
	select {
	case s.healthCh <- st:
	case <-s.closeCh:
	}
}

// ForceResend asks the session to re-emit the current status. Used by the
// manager when a config update arrives that did not change the merged config
// (e.g. user toggled output.status_reporting): we want consumers to see the
// latest collector status even though nothing in the collector changed.
func (s *opampSession) ForceResend() {
	select {
	case s.forceCh <- struct{}{}:
	default:
		// already pending
	}
}

// close terminates the session goroutine and waits for it to exit.
func (s *opampSession) close() {
	select {
	case <-s.closeCh:
		// already closed
	default:
		close(s.closeCh)
	}
	<-s.doneCh
}

// run is the session goroutine. It emits an initial StatusStarting and then
// loops on health updates, force-resend signals, and the watchdog timer.
// Close stops the goroutine without emitting any final status — the manager
// is responsible for any "collector gone" signaling that downstream needs.
func (s *opampSession) run(ctx context.Context) {
	defer close(s.doneCh)

	watchdogDuration := s.watchdogDuration
	if watchdogDuration == 0 {
		watchdogDuration = opampWatchdogDuration
	}

	current := status.AggregateStatus(componentstatus.StatusStarting, nil)
	s.statusFn(ctx, current)

	timer := time.NewTimer(watchdogDuration)
	defer timer.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case st := <-s.healthCh:
			// reset the watchdog on every successful delivery
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(watchdogDuration)

			if !status.CompareStatuses(current, st) {
				current = st
				s.statusFn(ctx, st)
			}
		case <-s.forceCh:
			s.statusFn(ctx, current)
		case <-timer.C:
			failed := status.AggregateStatus(
				componentstatus.StatusRecoverableError,
				errors.New(failedToConnectErrMsg),
			)
			if !status.CompareStatuses(current, failed) {
				current = failed
				s.statusFn(ctx, failed)
			}
		}
	}
}

// opampLoggerAdapter adapts elastic-agent's *logger.Logger to opamp-go's
// client/types.Logger interface used by the opamp server.
type opampLoggerAdapter struct {
	log *logger.Logger
}

func (a opampLoggerAdapter) Debugf(_ context.Context, format string, v ...any) {
	a.log.Debugf(format, v...)
}

func (a opampLoggerAdapter) Errorf(_ context.Context, format string, v ...any) {
	a.log.Errorf(format, v...)
}
