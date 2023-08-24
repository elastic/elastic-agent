// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"fmt"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	moncfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func InjectAPMConfig(comps []component.Component, cfg map[string]interface{}) ([]component.Component, error) {

	tracesEnabled, err := getAPMTracesEnabled(cfg)
	if err != nil {
		return comps, fmt.Errorf("error retrieving traces flag: %w", err)
	}

	if !tracesEnabled {
		// nothing to do
		return comps, nil
	}

	apmConfig, err := getAPMConfigFromMap(cfg)
	if err != nil {
		return comps, fmt.Errorf("error retrieving apm config: %w", err)
	}

	if apmConfig == nil {
		// nothing to do
		return comps, nil
	}

	for i := range comps {
		// We shouldn't really go straight from config datamodel to protobuf datamodel (a core datamodel would be nice to
		// abstract from protocol details)
		if comps[i].Component == nil {
			comps[i].Component = new(proto.Component)
		}
		comps[i].Component.ApmConfig = runtime.MapAPMConfig(apmConfig)
	}

	return comps, nil
}

func getAPMTracesEnabled(cfg map[string]any) (bool, error) {

	rawTracesEnabled, err := utils.GetNestedMap(cfg, "agent", "monitoring", "traces")
	if errors.Is(err, utils.ErrKeyNotFound) {
		// We didn't find the key, return false without any error
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("error accessing trace flag: %w", err)
	}

	traceEnabled, ok := rawTracesEnabled.(bool)
	if !ok {
		return false, fmt.Errorf("trace flag has unexpected type %T", rawTracesEnabled)
	}

	return traceEnabled, nil
}

func getAPMConfigFromMap(cfg map[string]any) (*moncfg.APMConfig, error) {
	nestedValue, err := utils.GetNestedMap(cfg, "agent", "monitoring", "apm")
	if errors.Is(err, utils.ErrKeyNotFound) {
		// No APM config found, nothing to do
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("error traversing config: %w", err)
	}

	rawApmConfig, ok := nestedValue.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the retrieved apm configs is not a map: %T", nestedValue)
	}

	monitoringConfig := new(moncfg.APMConfig)
	newConfigFrom, err := config.NewConfigFrom(rawApmConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing apm config: %w", err)
	}

	err = newConfigFrom.Unpack(monitoringConfig)
	if err != nil {
		return nil, fmt.Errorf("error unpacking apm config: %w", err)
	}
	return monitoringConfig, nil
}

func noop(change coordinator.ConfigChange) coordinator.ConfigChange {
	return change
}

func PatchAPMConfig(log *logger.Logger, rawConfig *config.Config) func(change coordinator.ConfigChange) coordinator.ConfigChange {
	configMap, err := rawConfig.ToMapStr()
	if err != nil {
		log.Errorf("error decoding raw config, patching disabled: %v", err)
		return noop
	}

	tracesEnabled, err := getAPMTracesEnabled(configMap)
	if err != nil {
		log.Errorf("error retrieving trace flag, patching disabled: %v", err)
		return noop
	}

	apmConfig, err := getAPMConfigFromMap(configMap)

	if err != nil {
		log.Errorf("error retrieving apm config, patching disabled: %v", err)
		return noop
	}

	if !tracesEnabled && apmConfig == nil {
		// traces disabled and no apm config -> no patching happening
		log.Debugf("traces disabled and no apm config: no patching necessary")
		return noop
	}
	monitoringPatch := map[string]any{"traces": tracesEnabled}
	if apmConfig != nil {
		monitoringPatch["apm"] = apmConfig
	}

	return func(change coordinator.ConfigChange) coordinator.ConfigChange {
		err := change.Config().Merge(map[string]any{"agent": map[string]any{"monitoring": monitoringPatch}})
		if err != nil {
			log.Errorf("error patching apm config into configchange: %v", err)
		}

		return change
	}
}
