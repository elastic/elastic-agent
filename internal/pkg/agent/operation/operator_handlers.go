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
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configrequest"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/core/app"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

type handleFunc func(step configrequest.Step) error

func (o *Operator) initHandlerMap() {
	hm := make(map[string]handleFunc)

	hm[configrequest.StepRun] = o.handleRun
	hm[configrequest.StepRemove] = o.handleRemove

	o.handlers = hm
}

func (o *Operator) handleRun(step configrequest.Step) error {
	if step.ProgramSpec.Cmd == monitoringName {
		return o.handleStartSidecar(step)
	}

	p, cfg, err := getProgramFromStep(step, o.config.DownloadConfig)
	if err != nil {
		return errors.New(err,
			"operator.handleStart failed to create program",
			errors.TypeApplication,
			errors.M(errors.MetaKeyAppName, step.ProgramSpec.Cmd))
	}

	return o.start(p, cfg)
}

func (o *Operator) handleRemove(step configrequest.Step) error {
	o.logger.Debugf("stopping process %s: %s", step.ProgramSpec.Cmd, step.ID)
	if step.ProgramSpec.Cmd == monitoringName {
		return o.handleStopSidecar(step)
	}

	p, _, err := getProgramFromStep(step, o.config.DownloadConfig)
	if err != nil {
		return errors.New(err,
			"operator.handleRemove failed to stop program",
			errors.TypeApplication,
			errors.M(errors.MetaKeyAppName, step.ProgramSpec.Cmd))
	}

	return o.stop(p)
}

func getProgramFromStep(step configrequest.Step, artifactConfig *artifact.Config) (Descriptor, map[string]interface{}, error) {
	return getProgramFromStepWithTags(step, artifactConfig, nil)
}

func getProgramFromStepWithTags(step configrequest.Step, artifactConfig *artifact.Config, tags map[app.Tag]string) (Descriptor, map[string]interface{}, error) {
	config, err := getConfigFromStep(step)
	if err != nil {
		return nil, nil, err
	}

	version := step.Version
	if release.Snapshot() {
		version = fmt.Sprintf("%s-SNAPSHOT", version)
	}

	p := app.NewDescriptor(step.ProgramSpec, version, artifactConfig, tags)
	return p, config, nil
}

func getConfigFromStep(step configrequest.Step) (map[string]interface{}, error) {
	metConfig, hasConfig := step.Meta[configrequest.MetaConfigKey]

	if !hasConfig && needsMetaConfig(step) {
		return nil, fmt.Errorf("step: %s, no config in metadata", step.ID)
	}

	var config map[string]interface{}
	if hasConfig {
		var ok bool
		config, ok = metConfig.(map[string]interface{})
		if !ok {
			return nil, errors.New(errors.TypeConfig,
				fmt.Sprintf("step: %s, program config is in invalid format", step.ID))
		}
	}

	return config, nil
}

func needsMetaConfig(step configrequest.Step) bool {
	return step.ID == configrequest.StepRun
}
