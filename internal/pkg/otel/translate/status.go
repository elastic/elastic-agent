// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/pipeline"
	"strings"
)

func GetComponentStatus(otelStatus status.AggregateStatus, components []component.Component) ([]runtime.ComponentComponentState, error) {
	var componentStates []runtime.ComponentComponentState
	return componentStates, nil
}

func getOtelRuntimePipelines(otelStatus status.AggregateStatus) (map[string]*status.AggregateStatus, error) {
	var pipelines map[string]*status.AggregateStatus
	for pipelineIdStr, status := range otelStatus.ComponentStatusMap {
		pipelineId := &pipeline.ID{}
		err := pipelineId.UnmarshalText([]byte(pipelineIdStr))
		if err != nil {
			return nil, err
		}
		if componentID, found := strings.CutPrefix(pipelineId.Name(), OtelNamePrefix); found {
			pipelines[componentID] = status
		}

	}
	return pipelines, nil
}
