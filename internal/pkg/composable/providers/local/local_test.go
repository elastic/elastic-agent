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

package local

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-poc/internal/pkg/composable"
	ctesting "github.com/elastic/elastic-agent-poc/internal/pkg/composable/testing"
	"github.com/elastic/elastic-agent-poc/internal/pkg/config"
)

func TestContextProvider(t *testing.T) {
	mapping := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}
	cfg, err := config.NewConfigFrom(map[string]interface{}{
		"vars": mapping,
	})
	require.NoError(t, err)
	builder, _ := composable.Providers.GetContextProvider("local")
	provider, err := builder(nil, cfg)
	require.NoError(t, err)

	comm := ctesting.NewContextComm(context.Background())
	err = provider.Run(comm)
	require.NoError(t, err)

	assert.Equal(t, mapping, comm.Current())
}
