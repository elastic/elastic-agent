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

package hooks

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/agent/program"
)

type embeddedUninstaller interface {
	Uninstall(ctx context.Context, spec program.Spec, version, installDir string) error
}

// Uninstaller that executes PreUninstallSteps
type Uninstaller struct {
	uninstaller embeddedUninstaller
}

// NewUninstaller creates an uninstaller that executes PreUninstallSteps
func NewUninstaller(i embeddedUninstaller) (*Uninstaller, error) {
	return &Uninstaller{
		uninstaller: i,
	}, nil
}

// Uninstall performs the execution of the PreUninstallSteps
func (i *Uninstaller) Uninstall(ctx context.Context, spec program.Spec, version, installDir string) error {
	if spec.PreUninstallSteps != nil {
		return spec.PreUninstallSteps.Execute(ctx, installDir)
	}
	return i.uninstaller.Uninstall(ctx, spec, version, installDir)
}
