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

package restart

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/control"
	"github.com/elastic/elastic-agent/internal/pkg/agent/control/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

// NewCommandWithArgs returns a new version command.
func NewCommandWithArgs(streams *cli.IOStreams) *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "Restart the currently running Elastic Agent daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := client.New()
			err := c.Connect(context.Background())
			if err != nil {
				return errors.New(err, "Failed communicating to running daemon", errors.TypeNetwork, errors.M("socket", control.Address()))
			}
			defer c.Disconnect()
			err = c.Restart(context.Background())
			if err != nil {
				return errors.New(err, "Failed trigger restart of daemon")
			}
			return nil
		},
	}
}
