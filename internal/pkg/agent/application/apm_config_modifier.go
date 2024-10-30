// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"fmt"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringcfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// InjectAPMConfig is a modifier passed to coordinator in order to set the global APM configuration used for the agent
// into each Component coming from input/output configuration
func InjectAPMConfig(comps []component.Component, cfg map[string]interface{}) ([]component.Component, error) {

	tracesEnabled, err := getAPMTracesEnabled(cfg)
	if err != nil {
		return comps, fmt.Errorf("error retrieving APM traces flag: %w", err)
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

func getAPMConfigFromMap(cfg map[string]any) (*monitoringcfg.APMConfig, error) {
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

	newConfigFrom, err := config.NewConfigFrom(rawApmConfig)
	if err != nil {
		return nil, fmt.Errorf("error parsing apm config: %w", err)
	}

	monitoringConfig := new(monitoringcfg.APMConfig)
	err = newConfigFrom.Unpack(monitoringConfig)
	if err != nil {
		return nil, fmt.Errorf("error unpacking apm config: %w", err)
	}
	return monitoringConfig, nil
}

func noop(change coordinator.ConfigChange) coordinator.ConfigChange {
	return change
}

// PatchAPMConfig is a temporary configuration patcher function (see ConfigPatchManager and ConfigPatch for reference) that
// will patch the configuration coming from Fleet adding the APM parameters from the elastic agent configuration file
// until Fleet supports this config directly
func PatchAPMConfig(log *logger.Logger, rawConfig *config.Config) func(change coordinator.ConfigChange) coordinator.ConfigChange {
	rawConfigMap, err := rawConfig.ToMapStr()
	if err != nil {
		log.Errorf("error decoding raw config, patching disabled: %v", err)
		return noop
	}

	log.Infof("Raw configuration: %s", rawConfigMap)

	tracesEnabledInRawCfg, err := getAPMTracesEnabled(rawConfigMap)
	if err != nil {
		log.Errorf("error retrieving trace flag, patching disabled: %v", err)
		return noop
	}

	apmConfig, err := getAPMConfigFromMap(rawConfigMap)
	if err != nil {
		log.Errorf("error retrieving apm config, patching disabled: %v", err)
		return noop
	}

	if !tracesEnabledInRawCfg && apmConfig == nil {
		// traces disabled and no apm config -> no patching happening
		log.Infof("traces disabled and no apm config: no patching necessary")
		return noop
	}
	monitoringPatch := map[string]any{"traces": tracesEnabledInRawCfg}
	if apmConfig != nil {
		monitoringPatch["apm"] = apmConfig
	}

	return func(change coordinator.ConfigChange) coordinator.ConfigChange {
		incomingChangeMap, err := change.Config().ToMapStr()
		if err != nil {
			log.Errorf("error trasforming incoming change into a map: %v", err)
			return change
		}

		_, err = utils.GetNestedMap(incomingChangeMap, "agent", "monitoring", "apm")

		if err == nil {
			// we found the apm config key in the incoming change -> don't modify the config
			log.Info("incoming change already contains APM config, no patching necessary")
			return change
		}

		if err != nil && !errors.Is(err, utils.ErrKeyNotFound) {
			// a generic error has happened
			log.Errorf("error checking incoming change for APM config: %v", err)
			return change
		}

		// We didn't find the APM config key in the incoming config change, we may need to patch
		incomingChangeTracesEnabled, err := getAPMTracesEnabled(incomingChangeMap)
		if err != nil {
			log.Errorf("error checking for monitoring.traces in configchange: %v", err)
			return change
		}

		if tracesEnabledInRawCfg || incomingChangeTracesEnabled {
			log.Infof("patching APM settings from config file: %v", monitoringPatch)
			err = change.Config().Merge(map[string]any{"agent": map[string]any{"monitoring": monitoringPatch}})
			if err != nil {
				log.Errorf("error patching apm config into configchange: %v", err)
			}
			return change
		}

		log.Infof("APM settings not patched: tracesEnabledInRawCfg=%v incomingChangeTracesEnabled=%v", tracesEnabledInRawCfg, incomingChangeTracesEnabled)
		return change
	}
}
