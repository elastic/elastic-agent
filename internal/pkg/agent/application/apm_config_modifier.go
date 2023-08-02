package application

import (
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	moncfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func InjectAPMConfig(comps []component.Component, cfg map[string]interface{}) ([]component.Component, error) {

	nestedValue, err := utils.GetNestedMap(cfg, "agent", "monitoring", "apm")
	if errors.Is(err, utils.ErrKeyNotFound) {
		// No APM config found, nothing to do
		return comps, nil
	}

	if err != nil {
		return comps, fmt.Errorf("error traversing config: %w", err)
	}

	rawApmConfig, ok := nestedValue.(map[string]any)
	if !ok {
		panic(fmt.Errorf("the retrieved apm configs is not a map: %T", nestedValue))
	}

	monitoringConfig := new(moncfg.APMConfig)
	newConfigFrom, err := config.NewConfigFrom(rawApmConfig)
	if err != nil {
		return comps, fmt.Errorf("error parsing apm config: %w", err)
	}

	err = newConfigFrom.Unpack(monitoringConfig)
	if err != nil {
		return comps, fmt.Errorf("error unpacking apm config: %w", err)
	}

	for i, _ := range comps {
		comps[i].APM = new(component.APMConfig)
		comps[i].APM.Elastic = (*component.ElasticAPM)(monitoringConfig)
	}

	return comps, nil
}
