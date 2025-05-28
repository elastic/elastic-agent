// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"go.opentelemetry.io/collector/confmap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"

	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var (
	netListen = net.Listen
)

const (
	// healthcheckv2 extension configuration settings
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/healthcheckv2extension
	healthCheckExtensionName            = "healthcheckv2"
	healthCheckIncludePermanentErrors   = true
	healthCheckIncludeRecoverableErrors = true
	healthCheckRecoveryDuration         = "5m"
	healthCheckHealthStatusPath         = "/health/status"
	healthCheckHealthStatusEnabled      = true
	healthCheckHealthConfigPath         = "/health/config"
	healthCheckHealthConfigEnabled      = false
)

type SerializableStatus struct {
	StartTimestamp *time.Time `json:"start_time,omitempty"`
	*SerializableEvent
	ComponentStatuses map[string]*SerializableStatus `json:"components,omitempty"`
}

// SerializableEvent is exported for json.Unmarshal
type SerializableEvent struct {
	Healthy      bool      `json:"healthy"`
	StatusString string    `json:"status"`
	Error        string    `json:"error,omitempty"`
	Timestamp    time.Time `json:"status_time"`
}

var stringToStatusMap = map[string]componentstatus.Status{
	"StatusNone":             componentstatus.StatusNone,
	"StatusStarting":         componentstatus.StatusStarting,
	"StatusOK":               componentstatus.StatusOK,
	"StatusRecoverableError": componentstatus.StatusRecoverableError,
	"StatusPermanentError":   componentstatus.StatusPermanentError,
	"StatusFatalError":       componentstatus.StatusFatalError,
	"StatusStopping":         componentstatus.StatusStopping,
	"StatusStopped":          componentstatus.StatusStopped,
}

type healthCheckEvent struct {
	status    componentstatus.Status
	timestamp time.Time
	err       error
}

func (e *healthCheckEvent) Status() componentstatus.Status { return e.status }
func (e *healthCheckEvent) Timestamp() time.Time           { return e.timestamp }
func (e *healthCheckEvent) Err() error                     { return e.err }

type healthChecker struct {
	stream     grpc.ServerStreamingClient[healthpb.HealthCheckResponse]
	clientConn *grpc.ClientConn
}

func (h *healthChecker) Recv() (*healthpb.HealthCheckResponse, error) {
	if h.stream == nil {
		return nil, errors.New("stream of healthcheck is nil")
	}
	return h.stream.Recv()
}

func (h *healthChecker) AllComponentsStatuses(ctx context.Context, httpHealthCheckPort int) (*status.AggregateStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://localhost:%d/%s?verbose",
		httpHealthCheckPort, healthCheckHealthStatusPath), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	client := http.DefaultClient
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get status: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	serStatus := &SerializableStatus{}
	err = json.Unmarshal(body, serStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal serializable status: %w", err)
	}

	return fromSerializableStatus(serStatus), nil
}

// fromSerializableEvent reconstructs a status.Event from SerializableEvent.
func fromSerializableEvent(se *SerializableEvent) status.Event {
	var err error
	if se.Error != "" {
		err = errors.New(se.Error)
	}

	statusVal, ok := stringToStatusMap[se.StatusString]
	if !ok {
		statusVal = componentstatus.StatusNone
	}

	return &healthCheckEvent{
		status:    statusVal,
		timestamp: se.Timestamp,
		err:       err,
	}
}

// fromSerializableStatus reconstructs an AggregateStatus from serializableStatus.
func fromSerializableStatus(ss *SerializableStatus) *status.AggregateStatus {
	ev := fromSerializableEvent(ss.SerializableEvent)

	as := &status.AggregateStatus{
		Event:              ev,
		ComponentStatusMap: make(map[string]*status.AggregateStatus),
	}

	for k, cs := range ss.ComponentStatuses {
		as.ComponentStatusMap[k] = fromSerializableStatus(cs)
	}

	return as
}

func findRandomPort() (int, error) {
	l, err := netListen("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	port := l.Addr().(*net.TCPAddr).Port
	err = l.Close()
	if err != nil {
		return 0, err
	}
	if port == 0 {
		return 0, fmt.Errorf("failed to find random port")
	}

	return port, nil
}

func injectHeathCheckV2Extension(conf *confmap.Conf, httpHealthCheckPort, grpcHealthCheckPort int) error {
	err := conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
		"extensions": map[string]interface{}{
			healthCheckExtensionName: map[string]interface{}{
				"use_v2": true,
				"component_health": map[string]interface{}{
					"include_permanent_errors":   healthCheckIncludePermanentErrors,
					"include_recoverable_errors": healthCheckIncludeRecoverableErrors,
					"recovery_duration":          healthCheckRecoveryDuration,
				},
				"http": map[string]interface{}{
					"endpoint": fmt.Sprintf("localhost:%d", httpHealthCheckPort),
					"status": map[string]interface{}{
						"enabled": healthCheckHealthStatusEnabled,
						"path":    healthCheckHealthStatusPath,
					},
					"config": map[string]interface{}{
						"enabled": healthCheckHealthConfigEnabled,
						"path":    healthCheckHealthConfigPath,
					},
				},
				"grpc": map[string]interface{}{
					"endpoint":  fmt.Sprintf("localhost:%d", grpcHealthCheckPort),
					"transport": "tcp",
				},
			},
		},
	}))
	if err != nil {
		return fmt.Errorf("merge into extensions failed: %w", err)
	}
	serviceConf, err := conf.Sub("service")
	if err != nil {
		//nolint:nilerr // ignore the error, no service defined in the configuration
		// this is going to error by the collector any way no reason to pollute with more
		// error information that is not really related to the issue at the moment
		return nil
	}
	extensionsRaw := serviceConf.Get("extensions")
	if extensionsRaw == nil {
		// no extensions defined on service (easily add it)
		err = conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
			"service": map[string]interface{}{
				"extensions": []interface{}{healthCheckExtensionName},
			},
		}))
		if err != nil {
			return fmt.Errorf("merge into service::extensions failed: %w", err)
		}
		return nil
	}
	extensionsSlice, ok := extensionsRaw.([]interface{})
	if !ok {
		return fmt.Errorf("merge into service::extensions failed: expected []interface{}, got %T", extensionsRaw)
	}
	for _, extensionRaw := range extensionsSlice {
		extension, ok := extensionRaw.(string)
		if ok && extension == healthCheckExtensionName {
			// already present, nothing to do
			return nil
		}
	}
	extensionsSlice = append(extensionsSlice, healthCheckExtensionName)
	err = conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
		"service": map[string]interface{}{
			"extensions": extensionsSlice,
		},
	}))
	if err != nil {
		return fmt.Errorf("merge into service::extensions failed: %w", err)
	}
	return nil
}
