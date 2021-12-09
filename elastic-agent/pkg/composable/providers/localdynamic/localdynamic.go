// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package localdynamic

import (
	"fmt"
	"strconv"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/composable"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/config"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
)

// ItemPriority is the priority that item mappings are added to the provider.
const ItemPriority = 0

func init() {
	composable.Providers.AddDynamicProvider("local_dynamic", DynamicProviderBuilder)
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
		if err := comm.AddOrUpdate(strconv.Itoa(i), ItemPriority, item.Mapping, item.Processors); err != nil {
			return errors.New(err, fmt.Sprintf("failed to add mapping for index %d", i), errors.TypeUnexpected)
		}
	}
	return nil
}

// DynamicProviderBuilder builds the dynamic provider.
func DynamicProviderBuilder(_ *logger.Logger, c *config.Config) (composable.DynamicProvider, error) {
	p := &dynamicProvider{}
	if c != nil {
		err := c.Unpack(p)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack vars: %s", err)
		}
	}
	if p.Items == nil {
		p.Items = []dynamicItem{}
	}
	return p, nil
}
