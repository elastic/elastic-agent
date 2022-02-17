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
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/core/state"
)

// operationVerify verifies downloaded artifact for correct signature
// skips if artifact is already installed
type operationVerify struct {
	program        Descriptor
	operatorConfig *configuration.SettingsConfig
	verifier       download.Verifier
}

func newOperationVerify(
	program Descriptor,
	operatorConfig *configuration.SettingsConfig,
	verifier download.Verifier) *operationVerify {
	return &operationVerify{
		program:        program,
		operatorConfig: operatorConfig,
		verifier:       verifier,
	}
}

// Name is human readable name identifying an operation
func (o *operationVerify) Name() string {
	return "operation-verify"
}

// Check checks whether verify needs to occur.
//
// Only if the artifacts exists does it need to be verified.
func (o *operationVerify) Check(_ context.Context, _ Application) (bool, error) {
	downloadConfig := o.operatorConfig.DownloadConfig
	fullPath, err := artifact.GetArtifactPath(o.program.Spec(), o.program.Version(), downloadConfig.OS(), downloadConfig.Arch(), downloadConfig.TargetDirectory)
	if err != nil {
		return false, err
	}

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return false, errors.New(errors.TypeApplication,
			fmt.Sprintf("%s.%s package does not exist in %s. Skipping operation %s", o.program.BinaryName(), o.program.Version(), fullPath, o.Name()))
	}

	return true, err
}

// Run runs the operation
func (o *operationVerify) Run(_ context.Context, application Application) (err error) {
	defer func() {
		if err != nil {
			application.SetState(state.Failed, err.Error(), nil)
		}
	}()

	isVerified, err := o.verifier.Verify(o.program.Spec(), o.program.Version(), true)
	if err != nil {
		return errors.New(err,
			fmt.Sprintf("operation '%s' failed to verify %s.%s", o.Name(), o.program.BinaryName(), o.program.Version()),
			errors.TypeSecurity)
	}

	if !isVerified {
		return errors.New(err,
			fmt.Sprintf("operation '%s' marked '%s.%s' corrupted", o.Name(), o.program.BinaryName(), o.program.Version()),
			errors.TypeSecurity)
	}

	return nil
}
