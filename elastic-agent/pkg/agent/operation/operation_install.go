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

package operation

import (
	"context"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/configuration"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/artifact/install"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/state"
)

// operationInstall installs a artifact from predefined location
// skips if artifact is already installed
type operationInstall struct {
	logger         *logger.Logger
	program        Descriptor
	operatorConfig *configuration.SettingsConfig
	installer      install.InstallerChecker
}

func newOperationInstall(
	logger *logger.Logger,
	program Descriptor,
	operatorConfig *configuration.SettingsConfig,
	installer install.InstallerChecker) *operationInstall {

	return &operationInstall{
		logger:         logger,
		program:        program,
		operatorConfig: operatorConfig,
		installer:      installer,
	}
}

// Name is human readable name identifying an operation
func (o *operationInstall) Name() string {
	return "operation-install"
}

// Check checks whether install needs to be ran.
//
// If the installation directory already exists then it will not be ran.
func (o *operationInstall) Check(ctx context.Context, _ Application) (bool, error) {
	err := o.installer.Check(ctx, o.program.Spec(), o.program.Version(), o.program.Directory())
	if err != nil {
		// don't return err, just state if Run should be called
		return true, nil
	}
	return false, nil
}

// Run runs the operation
func (o *operationInstall) Run(ctx context.Context, application Application) (err error) {
	defer func() {
		if err != nil {
			application.SetState(state.Failed, err.Error(), nil)
		}
	}()

	return o.installer.Install(ctx, o.program.Spec(), o.program.Version(), o.program.Directory())
}
