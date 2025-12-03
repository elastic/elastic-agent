// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func PatchFleetConfig(log *logger.Logger,
	rawConfig *config.Config, // original config from fleet, this one won't reload
	caps capabilities.Capabilities,
	isManaged bool,
) func(change coordinator.ConfigChange) coordinator.ConfigChange {
	if !isManaged || // no need to override fleet config when not managed
		caps == nil || !caps.AllowFleetOverride() {
		return noop
	}

	return func(change coordinator.ConfigChange) coordinator.ConfigChange {
		newConfig := change.Config()
		if err := newConfig.Merge(rawConfig); err != nil {
			log.Errorf("error merging fleet config into config change: %v", err)
		}

		return change
	}
}
