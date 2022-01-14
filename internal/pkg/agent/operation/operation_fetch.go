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
	"os"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent-poc/internal/pkg/artifact"
	"github.com/elastic/elastic-agent-poc/internal/pkg/artifact/download"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/state"
)

// operationFetch fetches artifact from preconfigured source
// skips if artifact is already downloaded
type operationFetch struct {
	logger         *logger.Logger
	program        Descriptor
	operatorConfig *configuration.SettingsConfig
	downloader     download.Downloader
}

func newOperationFetch(
	logger *logger.Logger,
	program Descriptor,
	operatorConfig *configuration.SettingsConfig,
	downloader download.Downloader) *operationFetch {

	return &operationFetch{
		logger:         logger,
		program:        program,
		operatorConfig: operatorConfig,
		downloader:     downloader,
	}
}

// Name is human readable name identifying an operation
func (o *operationFetch) Name() string {
	return "operation-fetch"
}

// Check checks whether fetch needs to occur.
//
// If the artifacts already exists then fetch will not be ran.
func (o *operationFetch) Check(_ context.Context, _ Application) (bool, error) {
	downloadConfig := o.operatorConfig.DownloadConfig
	fullPath, err := artifact.GetArtifactPath(o.program.Spec(), o.program.Version(), downloadConfig.OS(), downloadConfig.Arch(), downloadConfig.TargetDirectory)
	if err != nil {
		return false, err
	}

	_, err = os.Stat(fullPath)
	if os.IsNotExist(err) {
		return true, nil
	}

	o.logger.Debugf("binary '%s.%s' already exists in %s. Skipping operation %s", o.program.BinaryName(), o.program.Version(), fullPath, o.Name())
	return false, err
}

// Run runs the operation
func (o *operationFetch) Run(ctx context.Context, application Application) (err error) {
	defer func() {
		if err != nil {
			application.SetState(state.Failed, err.Error(), nil)
		}
	}()

	fullPath, err := o.downloader.Download(ctx, o.program.Spec(), o.program.Version())
	if err == nil {
		o.logger.Infof("downloaded binary '%s.%s' into '%s' as part of operation '%s'", o.program.BinaryName(), o.program.Version(), fullPath, o.Name())
	}

	return err
}
