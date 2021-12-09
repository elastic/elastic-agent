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

package process

import (
	"context"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/plugin"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/state"
)

// Configure configures the application with the passed configuration.
func (a *Application) Configure(ctx context.Context, config map[string]interface{}) (err error) {
	defer func() {
		if err != nil {
			// inject App metadata
			err = errors.New(err, errors.M(errors.MetaKeyAppName, a.name), errors.M(errors.MetaKeyAppName, a.id))
			a.statusReporter.Update(state.Degraded, err.Error(), nil)
		}
	}()

	a.appLock.Lock()
	defer a.appLock.Unlock()

	if a.state.Status == state.Stopped {
		return errors.New(ErrAppNotRunning)
	}
	if a.srvState == nil {
		return errors.New(ErrAppNotRunning)
	}

	cfgStr, err := yaml.Marshal(config)
	if err != nil {
		return errors.New(err, errors.TypeApplication)
	}

	isRestartNeeded := plugin.IsRestartNeeded(a.logger, a.Spec(), a.srvState, config)

	err = a.srvState.UpdateConfig(string(cfgStr))
	if err != nil {
		return errors.New(err, errors.TypeApplication)
	}

	if isRestartNeeded {
		a.logger.Infof("initiating restart of '%s' due to config change", a.Name())
		a.appLock.Unlock()
		a.Stop()
		err = a.Start(ctx, a.desc, config)
		// lock back so it wont panic on deferred unlock
		a.appLock.Lock()
	}

	return err
}
