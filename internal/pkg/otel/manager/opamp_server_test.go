// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	otelstatus "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componentstatus"
	"google.golang.org/protobuf/proto"

	internalstatus "github.com/elastic/elastic-agent/internal/pkg/otel/status"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// sessionCapture mirrors monitorCapture from execution_subprocess_test.go: it
// collects statuses passed to the statusFn closure under a mutex so tests can
// snapshot them safely after a synctest.Wait.
type sessionCapture struct {
	mu       sync.Mutex
	statuses []*otelstatus.AggregateStatus
}

func (c *sessionCapture) record(_ context.Context, st *otelstatus.AggregateStatus) {
	c.mu.Lock()
	c.statuses = append(c.statuses, st)
	c.mu.Unlock()
}

func (c *sessionCapture) snapshot() []*otelstatus.AggregateStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*otelstatus.AggregateStatus, len(c.statuses))
	copy(out, c.statuses)
	return out
}

func newTestSession(t *testing.T) (*opampSession, *sessionCapture) {
	t.Helper()
	log, err := logger.New("test", false)
	require.NoError(t, err)

	cap := &sessionCapture{}
	sess := &opampSession{
		log:              log,
		statusFn:         cap.record,
		healthCh:         make(chan *otelstatus.AggregateStatus, 1),
		forceCh:          make(chan struct{}, 1),
		closeCh:          make(chan struct{}),
		doneCh:           make(chan struct{}),
		watchdogDuration: opampWatchdogDuration,
	}
	return sess, cap
}

// TestOpAMPSession_StartingThenStatusFlow covers the same scenarios that
// previously lived in TestProcHandle_MonitorHealth but at the opamp session
// layer where the logic now lives.
func TestOpAMPSession_StartingThenStatusFlow(t *testing.T) {
	t.Run("initial_starting_emitted_immediately", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sess, cap := newTestSession(t)
			go sess.run(t.Context())
			synctest.Wait()

			statuses := cap.snapshot()
			require.Len(t, statuses, 1)
			require.NotNil(t, statuses[0])
			assert.Equal(t, componentstatus.StatusStarting, statuses[0].Status())

			t.Cleanup(sess.close)
		})
	})

	t.Run("reports_status_change", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sess, cap := newTestSession(t)
			go sess.run(t.Context())
			synctest.Wait()

			ok := internalstatus.AggregateStatus(componentstatus.StatusOK, nil)
			sess.deliverHealth(ok)
			synctest.Wait()

			statuses := cap.snapshot()
			require.Len(t, statuses, 2)
			assert.Equal(t, componentstatus.StatusStarting, statuses[0].Status())
			require.NotNil(t, statuses[1])
			assert.Equal(t, componentstatus.StatusOK, statuses[1].Status())

			t.Cleanup(sess.close)
		})
	})

	t.Run("no_report_when_status_unchanged", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sess, cap := newTestSession(t)
			go sess.run(t.Context())
			synctest.Wait()

			ok := internalstatus.AggregateStatus(componentstatus.StatusOK, nil)
			sess.deliverHealth(ok)
			synctest.Wait()
			// Re-deliver the same pointer: timestamps match → CompareStatuses true.
			sess.deliverHealth(ok)
			synctest.Wait()

			statuses := cap.snapshot()
			// Starting + first OK only; the duplicate must not be emitted.
			assert.Len(t, statuses, 2)

			t.Cleanup(sess.close)
		})
	})

	t.Run("force_resend_re_emits_current_status", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sess, cap := newTestSession(t)
			go sess.run(t.Context())
			synctest.Wait()

			ok := internalstatus.AggregateStatus(componentstatus.StatusOK, nil)
			sess.deliverHealth(ok)
			synctest.Wait()

			require.Len(t, cap.snapshot(), 2)

			sess.ForceResend()
			synctest.Wait()

			statuses := cap.snapshot()
			require.Len(t, statuses, 3)
			require.NotNil(t, statuses[2])
			assert.Equal(t, componentstatus.StatusOK, statuses[2].Status())

			t.Cleanup(sess.close)
		})
	})

	t.Run("force_resend_uses_current_status_after_change", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sess, cap := newTestSession(t)
			go sess.run(t.Context())
			synctest.Wait()

			sess.deliverHealth(internalstatus.AggregateStatus(componentstatus.StatusOK, nil))
			synctest.Wait()

			degraded := internalstatus.AggregateStatus(
				componentstatus.StatusRecoverableError, errors.New("test error"))
			sess.deliverHealth(degraded)
			synctest.Wait()

			statuses := cap.snapshot()
			require.Len(t, statuses, 3)
			assert.Equal(t, componentstatus.StatusRecoverableError, statuses[2].Status())

			sess.ForceResend()
			synctest.Wait()

			statuses = cap.snapshot()
			require.Len(t, statuses, 4)
			require.NotNil(t, statuses[3])
			assert.Equal(t, componentstatus.StatusRecoverableError, statuses[3].Status())
			require.Error(t, statuses[3].Err())
			assert.Equal(t, "test error", statuses[3].Err().Error())

			t.Cleanup(sess.close)
		})
	})

	t.Run("watchdog_emits_recoverable_error_after_silence", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sess, cap := newTestSession(t)
			go sess.run(t.Context())
			synctest.Wait()

			require.Len(t, cap.snapshot(), 1)

			// Advance fake time past the watchdog duration without delivering
			// any health updates.
			time.Sleep(opampWatchdogDuration + time.Second)
			synctest.Wait()

			statuses := cap.snapshot()
			require.Len(t, statuses, 2)
			require.NotNil(t, statuses[1])
			assert.Equal(t, componentstatus.StatusRecoverableError, statuses[1].Status())
			require.Error(t, statuses[1].Err())
			assert.Equal(t, failedToConnectErrMsg, statuses[1].Err().Error())

			t.Cleanup(sess.close)
		})
	})

	t.Run("delivery_resets_watchdog", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sess, cap := newTestSession(t)
			go sess.run(t.Context())
			synctest.Wait()

			// Almost full duration with a delivery before expiry.
			time.Sleep(opampWatchdogDuration - 5*time.Second)
			sess.deliverHealth(internalstatus.AggregateStatus(componentstatus.StatusOK, nil))
			synctest.Wait()

			// Sleep long enough that without a reset the watchdog would have fired.
			time.Sleep(10 * time.Second)
			synctest.Wait()

			statuses := cap.snapshot()
			// Starting + OK; no failed-to-connect emitted.
			require.Len(t, statuses, 2)
			assert.Equal(t, componentstatus.StatusOK, statuses[1].Status())

			t.Cleanup(sess.close)
		})
	})
}

// TestOpAMPServer_HTTP exercises the embedded HTTP server end-to-end: bind,
// authentication enforcement, and Health translation through to the active
// session.
func TestOpAMPServer_HTTP(t *testing.T) {
	log, err := logger.New("test", false)
	require.NoError(t, err)

	srv := newOpAMPServer(log, "secret-1234")
	require.NoError(t, srv.Start("127.0.0.1:0"))
	t.Cleanup(func() {
		_ = srv.Stop(context.Background())
	})

	endpoint := srv.Endpoint()
	require.NotEmpty(t, endpoint)
	require.Contains(t, endpoint, "http://127.0.0.1:")

	t.Run("missing_auth_returns_401", func(t *testing.T) {
		body := mustMarshalAgentToServer(t, &protobufs.AgentToServer{
			InstanceUid: []byte("test-instance"),
		})
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-protobuf")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("wrong_auth_returns_401", func(t *testing.T) {
		body := mustMarshalAgentToServer(t, &protobufs.AgentToServer{InstanceUid: []byte("x")})
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set(opampAuthorizationHeader, "Bearer wrong")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("valid_auth_with_health_reaches_active_session", func(t *testing.T) {
		cap := &sessionCapture{}
		sess := srv.StartSession(t.Context(), cap.record)
		t.Cleanup(srv.CloseSession)

		// Wait for the initial Starting emit.
		require.Eventually(t, func() bool { return len(cap.snapshot()) >= 1 },
			time.Second, 10*time.Millisecond)

		body := mustMarshalAgentToServer(t, &protobufs.AgentToServer{
			InstanceUid: []byte("instance-ok"),
			Health: &protobufs.ComponentHealth{
				Healthy: true,
				Status:  "StatusOK",
			},
		})
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set(opampAuthorizationHeader, "Bearer secret-1234")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// The session should observe StatusStarting then StatusOK.
		require.Eventually(t, func() bool {
			s := cap.snapshot()
			return len(s) >= 2 && s[len(s)-1] != nil &&
				s[len(s)-1].Status() == componentstatus.StatusOK
		}, time.Second, 10*time.Millisecond)

		_ = sess
	})

	t.Run("message_with_no_active_session_is_dropped", func(t *testing.T) {
		// No session in flight (previous subtest ran t.Cleanup(srv.CloseSession)).
		body := mustMarshalAgentToServer(t, &protobufs.AgentToServer{
			InstanceUid: []byte("orphan"),
			Health:      &protobufs.ComponentHealth{Status: "StatusOK"},
		})
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set(opampAuthorizationHeader, "Bearer secret-1234")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestGenerateOpAMPSecret(t *testing.T) {
	a, err := generateOpAMPSecret()
	require.NoError(t, err)
	b, err := generateOpAMPSecret()
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
	assert.Len(t, a, 64)
}

func mustMarshalAgentToServer(t *testing.T, msg *protobufs.AgentToServer) []byte {
	t.Helper()
	b, err := proto.Marshal(msg)
	require.NoError(t, err)
	return b
}
