// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package localdynamic

import (
	"fmt"
	"strconv"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// ItemPriority is the priority that item mappings are added to the provider.
const ItemPriority = 0

func init() {
	composable.Providers.MustAddDynamicProvider("local_dynamic", DynamicProviderBuilder)
}

type dynamicItem struct {
	Mapping    map[string]interface{}   `config:"vars"`
	Processors []map[string]interface{} `config:"processors"`
}

type dynamicProvider struct {
	Items []dynamicItem `config:"items"`
}

// Run runs the environment context provider.
func (c *dynamicProvider) Run(comm composable.DynamicProviderComm) error {
	for i, item := range c.Items {
		if err := comm.AddOrUpdate(strconv.Itoa(i), ItemPriority, item.Mapping, item.Processors, nil); err != nil {
			return errors.New(err, fmt.Sprintf("failed to add mapping for index %d", i), errors.TypeUnexpected)
		}
	}
	return nil
}

// DynamicProviderBuilder builds the dynamic provider.
func DynamicProviderBuilder(_ *logger.Logger, c *config.Config, _ bool) (composable.DynamicProvider, error) {
	p := &dynamicProvider{}
	if c != nil {
		err := c.Unpack(p)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack vars: %w", err)
		}
	}
	if p.Items == nil {
		p.Items = []dynamicItem{}
	}
	return p, nil
}
