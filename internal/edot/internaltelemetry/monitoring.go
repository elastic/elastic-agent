// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package internaltelemetry

const (
	// EventTypeAttr is the scope attribute key encoding the type of monitoring
	// event represented by a ScopeMetrics group in the elasticmonitoringprocessor's
	// output.
	EventTypeAttr = "elastic.monitoring.event.type"

	EventTypeExporter = "exporter"
	EventTypeInput    = "input"
	EventTypeReceiver = "receiver"

	// ComponentIDAttr is the scope attribute key for the agent component ID.
	ComponentIDAttr = "component.id"

	// InputIDAttr is the scope attribute key for the input ID (input events only).
	InputIDAttr = "input.id"

	// InputTypeAttr is the scope attribute key for the input type (input events only).
	InputTypeAttr = "input.type"

	// ScopeName is the instrumentation scope name set on the elasticmonitoringprocessor's
	// output metrics.
	ScopeName = "github.com/elastic/elastic-agent/internal/edot/internaltelemetry"
)
