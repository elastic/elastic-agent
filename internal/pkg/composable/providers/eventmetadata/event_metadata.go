// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package eventmetadata

import (
	"context"
	"errors"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	providersConfigKey         = "providers"
	eventMetadataProcessorName = "event_metadata"
)

type globalProviderConfig struct {
	Enabled bool           `json:"enabled" mapstructure:"enabled"`
	Config  map[string]any `json:",inline" mapstructure:",remain"`
}

type globalProvidersProvider struct {
}

func (e *globalProvidersProvider) Run(ctx context.Context, comm corecomp.ContextProviderComm) error {
	// This event provider is really implemented by a coordinator ComponentModifier below, this is here just to allow
	// the poor soul looking for `providers[event_metadata]` to find this where it is expected to be
	// Do nothing in this function
	return nil
}

func SetGlobalProcessorConfig(comps []component.Component, cfg map[string]interface{}) ([]component.Component, error) {
	eventMetadataConfig, err := utils.GetNestedMap(cfg, providersConfigKey, eventMetadataProcessorName)
	if errors.Is(err, utils.ErrKeyNotFound) {
		// providers.event_metadata has not been found, nothing to do
		return comps, nil
	}

	if err != nil {
		return comps, fmt.Errorf("looking for key %s.%s in configuration: %w", providersConfigKey, eventMetadataProcessorName, err)
	}

	var configuredGlobalProviders map[string]globalProviderConfig
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{Result: &configuredGlobalProviders})
	if err != nil {
		return comps, fmt.Errorf("creating decoder for global processors config: %w", err)
	}

	err = decoder.Decode(eventMetadataConfig)
	if err != nil {
		return comps, fmt.Errorf("decoding global processors config: %w", err)
	}

	providerConfig, err := mapGlobalProviderConfig(configuredGlobalProviders)
	if err != nil {
		return comps, fmt.Errorf("mapping GlobalProviderConfig: %w", err)
	}

	if providerConfig == nil {
		return comps, nil
	}

	for i := range comps {
		if comps[i].Component == nil {
			comps[i].Component = new(proto.Component)
		}
		comps[i].Component.Processors = providerConfig
	}

	return comps, nil
}
