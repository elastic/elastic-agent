// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/pipeline"
)

// for testing purposes
var netListen = net.Listen

// reportErr sends an error to the provided error channel. It first drains the channel
// to ensure that only the most recent error is kept, as intermediate errors can be safely discarded.
// This ensures the receiver always observes the latest reported error.
func reportErr(ctx context.Context, errCh chan error, err error) {
	select {
	case <-ctx.Done():
		// context is already done
		return
	case <-errCh:
	// drain the error channel first
	default:
	}
	select {
	case errCh <- err:
	case <-ctx.Done():
	}
}

// reportCollectorStatus sends a status to the provided channel. It first drains the channel
// to ensure that only the most recent status is kept, as intermediate statuses can be safely discarded.
// This ensures the receiver always observes the latest reported status.
func reportCollectorStatus(ctx context.Context, statusCh chan *status.AggregateStatus, collectorStatus *status.AggregateStatus) {
	select {
	case <-ctx.Done():
		// context is already done
		return
	case <-statusCh:
	// drain the channel first
	default:
	}
	select {
	case <-ctx.Done():
		return
	case statusCh <- collectorStatus:
	}
}

// findRandomTCPPorts finds count random available TCP ports on the localhost interface.
func findRandomTCPPorts(count int) (ports []int, err error) {
	ports = make([]int, 0, count)
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			if closeErr := listener.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("error closing listener: %w", closeErr))
			}
		}
	}()
	for range count {
		l, err := netListen("tcp", "localhost:0")
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, l)

		port := l.Addr().(*net.TCPAddr).Port
		if port == 0 {
			return nil, fmt.Errorf("failed to find random port")
		}
		ports = append(ports, port)
	}

	return ports, err
}

// otelConfigToStatus converts the `cfg` to `status.AggregateStatus` using the reported error.
//
// The flow of this function comes from https://github.com/open-telemetry/opentelemetry-collector/blob/main/service/internal/graph/graph.go
// It's a much simpler version, but follows the same for loop ordering and building of connectors of the internal
// graph system that OTEL uses to build its component graph.
func otelConfigToStatus(cfg *confmap.Conf, err error) (*status.AggregateStatus, error) {
	// marshall into config
	var c otelcol.Config
	if unmarshalErr := cfg.Unmarshal(&c); unmarshalErr != nil {
		return nil, fmt.Errorf("could not unmarshal config: %w", unmarshalErr)
	}

	// should at least define a single pipeline
	if len(c.Service.Pipelines) == 0 {
		return nil, fmt.Errorf("no pipelines defined")
	}

	// aggregators are used to create the overall status structure
	// aggGeneric is used to for a generic aggregator status where all instances get the same error
	// aggSpecific is used to provide status to the specific instance that caused the error
	// aggSpecific is only used if matchOccurred is true
	aggGeneric := status.NewAggregator(status.PriorityPermanent)
	aggSpecific := status.NewAggregator(status.PriorityPermanent)
	matchOccurred := false

	// extensions
	for _, id := range c.Service.Extensions {
		instanceID := componentstatus.NewInstanceID(id, component.KindExtension)
		aggGeneric.RecordStatus(instanceID, componentstatus.NewFatalErrorEvent(err))
		if recordSpecificErr(aggSpecific, instanceID, err) {
			matchOccurred = true
		}
	}

	// track connectors
	connectors := make(map[component.ID]struct{})
	connectorsAsReceiver := make(map[component.ID][]pipeline.ID)
	connectorsAsExporter := make(map[component.ID][]pipeline.ID)

	// pipelines
	for pipelineID, pipelineCfg := range c.Service.Pipelines {
		for _, recvID := range pipelineCfg.Receivers {
			// upstream graph creates a single component instance for a set of pipelines, then status reporting
			// copies the instance for each pipeline. creating a unique instance per-pipeline provides the same
			// behavior.
			instanceID := componentstatus.NewInstanceID(recvID, component.KindReceiver, pipelineID)
			_, isConnector := c.Connectors[recvID]
			if isConnector {
				connectors[recvID] = struct{}{}
				connectorsAsReceiver[recvID] = append(connectorsAsReceiver[recvID], pipelineID)
			}
			aggGeneric.RecordStatus(instanceID, componentstatus.NewFatalErrorEvent(err))
			if recordSpecificErr(aggSpecific, instanceID, err) {
				matchOccurred = true
			}
		}
		for _, procID := range pipelineCfg.Processors {
			instanceID := componentstatus.NewInstanceID(procID, component.KindProcessor, pipelineID)
			aggGeneric.RecordStatus(instanceID, componentstatus.NewFatalErrorEvent(err))
			if recordSpecificErr(aggSpecific, instanceID, err) {
				matchOccurred = true
			}
		}
		for _, exporterID := range pipelineCfg.Exporters {
			instanceID := componentstatus.NewInstanceID(exporterID, component.KindExporter, pipelineID)
			_, isConnector := c.Connectors[exporterID]
			if isConnector {
				connectors[exporterID] = struct{}{}
				connectorsAsExporter[exporterID] = append(connectorsAsExporter[exporterID], pipelineID)
			}
			aggGeneric.RecordStatus(instanceID, componentstatus.NewFatalErrorEvent(err))
			if recordSpecificErr(aggSpecific, instanceID, err) {
				matchOccurred = true
			}
		}
	}

	// connectors
	for connID := range connectors {
		extraMatchStr := fmt.Sprintf("connector %q used as", connID)
		for _, eID := range connectorsAsExporter[connID] {
			for _, rID := range connectorsAsReceiver[connID] {
				instanceID := componentstatus.NewInstanceID(
					connID, component.KindConnector, eID, rID,
				)
				aggGeneric.RecordStatus(instanceID, componentstatus.NewFatalErrorEvent(err))
				if recordSpecificErr(aggSpecific, instanceID, err, extraMatchStr) {
					matchOccurred = true
				}
			}
		}
	}

	if matchOccurred {
		// specific for the matched error
		aggStatus, _ := aggSpecific.AggregateStatus(status.ScopeAll, status.Verbose)
		return aggStatus, nil
	}
	// no match found so generic failed on all instances
	aggStatus, _ := aggGeneric.AggregateStatus(status.ScopeAll, status.Verbose)
	return aggStatus, nil
}

func recordSpecificErr(agg *status.Aggregator, instanceID *componentstatus.InstanceID, err error, extraMatchStrs ...string) bool {
	// matches configuration errors for a specific component
	forIDStr := fmt.Sprintf("for id: %q", instanceID.ComponentID().String())
	// occurs when a specific component fails to start
	failedMatchStr := fmt.Sprintf("failed to start %q %s:", instanceID.ComponentID().String(), strings.ToLower(instanceID.Kind().String()))
	// occurs when a component factory is not available (unknown component type)
	factoryNotAvailableStr := fmt.Sprintf("factory not available for: %q", instanceID.ComponentID().String())
	if strings.Contains(err.Error(), forIDStr) || strings.Contains(err.Error(), failedMatchStr) || strings.Contains(err.Error(), factoryNotAvailableStr) {
		// specific so this instance gets the reported error
		agg.RecordStatus(instanceID, componentstatus.NewFatalErrorEvent(err))
		return true
	}
	// extra matchers
	for _, matchStr := range extraMatchStrs {
		if strings.Contains(err.Error(), matchStr) {
			// specific so this instance gets the reported error
			agg.RecordStatus(instanceID, componentstatus.NewFatalErrorEvent(err))
			return true
		}
	}
	// not specific to this instance, so we record this one as starting
	agg.RecordStatus(instanceID, componentstatus.NewEvent(componentstatus.StatusStarting))
	return false
}
