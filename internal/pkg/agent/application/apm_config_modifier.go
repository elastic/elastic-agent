package application

import (
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	moncfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func InjectAPMConfig(comps []component.Component, cfg map[string]interface{}) ([]component.Component, error) {

	apmConfig, err := getAPMConfigFromMap(cfg)
	if err != nil {
		return comps, fmt.Errorf("error injecting apm config: %w", err)
	}

	if apmConfig == nil {
		// nothing to do
		return comps, nil
	}

	for i, _ := range comps {
		comps[i].APM = new(component.APMConfig)
		comps[i].APM.Elastic = (*component.ElasticAPM)(apmConfig)
	}

	return comps, nil
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

	apmConfig, err := getAPMConfigFromMap(configMap)

	if err != nil {
		log.Errorf("error retrieving apm config, patching disabled: %v", err)
		return noop
	}

	if apmConfig == nil {
		log.Debug("no apm config set, patching disabled")
		return noop
	}

	return func(change coordinator.ConfigChange) coordinator.ConfigChange {
		err := change.Config().Merge(map[string]any{"agent": map[string]any{"monitoring": map[string]any{"apm": apmConfig}}})
		if err != nil {
			log.Errorf("error patching apm config into configchange: %v", err)
		}

		return change
	}
}
