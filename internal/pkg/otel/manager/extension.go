// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/extension"
	"go.uber.org/zap"
)

var AgentStatusExtensionType = component.MustNewType("agent_status")

type evtPair struct {
	source *componentstatus.InstanceID
	event  *componentstatus.Event
}

type AgentStatusExtension struct {
	mgr        *OTelManager
	telemetry  component.TelemetrySettings
	aggregator *status.Aggregator
	eventCh    chan *evtPair
	readyCh    chan struct{}
	kickCh     chan struct{}
	ctx        context.Context
	canceller  context.CancelFunc
	host       component.Host
}

// validate that the extension implements the required interfaces
var _ component.Component = (*AgentStatusExtension)(nil)
var _ componentstatus.Watcher = (*AgentStatusExtension)(nil)

// NewAgentStatusExtension returns the agent_status extension to be used by the
// OTel collector when running in hybrid mode.
func NewAgentStatusExtension(ctx context.Context, set extension.Settings, mgr *OTelManager) *AgentStatusExtension {
	ctx, cancel := context.WithCancel(ctx)
	aggregator := status.NewAggregator(status.PriorityRecoverable)
	as := &AgentStatusExtension{
		mgr:        mgr,
		telemetry:  set.TelemetrySettings,
		aggregator: aggregator,
		eventCh:    make(chan *evtPair),
		readyCh:    make(chan struct{}),
		kickCh:     make(chan struct{}, 1),
		ctx:        ctx,
		canceller:  cancel,
	}

	// start processing early as ComponentStatusChanged will be called before Start is called
	go as.eventLoop(ctx)

	return as
}

// NewAgentStatusFactory provides a factory for creating the AgentStatusExtension.
func NewAgentStatusFactory(mgr *OTelManager) extension.Factory {
	return extension.NewFactory(
		AgentStatusExtensionType,
		func() component.Config {
			return nil
		},
		func(ctx context.Context, set extension.Settings, cfg component.Config) (extension.Extension, error) {
			return NewAgentStatusExtension(ctx, set, mgr), nil
		},
		component.StabilityLevelDevelopment,
	)
}

// Start implements the component.Component interface.
func (as *AgentStatusExtension) Start(ctx context.Context, host component.Host) error {
	as.telemetry.Logger.Debug("Starting agent status extension")
	as.host = host
	return nil
}

// Shutdown implements the component.Component interface.
func (as *AgentStatusExtension) Shutdown(ctx context.Context) error {
	// preemptively send the stopped event, so it can be exported before shutdown
	componentstatus.ReportStatus(as.host, componentstatus.NewEvent(componentstatus.StatusStopped))
	as.canceller()
	return nil
}

// Ready implements the extension.PipelineWatcher interface.
func (as *AgentStatusExtension) Ready() error {
	close(as.readyCh)
	return nil
}

// NotReady implements the extension.PipelineWatcher interface.
func (as *AgentStatusExtension) NotReady() error {
	return nil
}

// ComponentStatusChanged implements the extension.StatusWatcher interface.
func (as *AgentStatusExtension) ComponentStatusChanged(
	source *componentstatus.InstanceID,
	event *componentstatus.Event,
) {
	// this extension is always force loaded and not by the user, so status
	// information should be hidden as they didn't directly enable it
	if source.ComponentID().String() == AgentStatusExtensionType.String() {
		return
	}
	// possible that even after Shutdown is called that this function is still
	// called by the coordinator
	defer func() {
		if r := recover(); r != nil {
			as.telemetry.Logger.Info(
				"discarding event received after shutdown",
				zap.Any("source", source),
				zap.Any("event", event),
			)
		}
	}()
	select {
	case as.eventCh <- &evtPair{source: source, event: event}:
	case <-as.ctx.Done():
	}
}

func (as *AgentStatusExtension) eventLoop(ctx context.Context) {
	// prevent aggregate statuses from flapping between StatusStarting and StatusOK
	// as components are started individually by the service.
	//
	// follows the same pattern that is being used by the healthcheckv2extension
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/extension/healthcheckv2extension/extension.go#L168
	var eventQueue []*evtPair

LOOP:
	for {
		select {
		case esp := <-as.eventCh:
			if esp.event.Status() != componentstatus.StatusStarting {
				eventQueue = append(eventQueue, esp)
				continue
			}
			as.aggregator.RecordStatus(esp.source, esp.event)
			as.triggerKickCh()
		case <-as.readyCh:
			if len(eventQueue) > 0 {
				for _, esp := range eventQueue {
					as.aggregator.RecordStatus(esp.source, esp.event)
				}
				as.triggerKickCh()
			}
			break LOOP
		case <-as.kickCh:
			as.publishStatus()
		case <-ctx.Done():
			as.aggregator.Close()
			return
		}
	}

	// After PipelineWatcher.Ready, record statuses as they are received.
	for {
		select {
		case esp := <-as.eventCh:
			as.aggregator.RecordStatus(esp.source, esp.event)
			as.triggerKickCh()
		case <-as.kickCh:
			as.publishStatus()
		case <-ctx.Done():
			as.aggregator.Close()
			return
		}
	}
}

func (as *AgentStatusExtension) triggerKickCh() {
	select {
	case as.kickCh <- struct{}{}:
	default:
	}
}

func (as *AgentStatusExtension) publishStatus() {
	current, _ := as.aggregator.AggregateStatus(status.ScopeAll, status.Verbose)
	as.mgr.statusCh <- current
}
