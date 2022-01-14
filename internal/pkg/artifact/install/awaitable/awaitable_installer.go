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

package awaitable

import (
	"context"
	"sync"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/program"
)

type embeddedInstaller interface {
	Install(ctx context.Context, spec program.Spec, version, installDir string) error
}

type embeddedChecker interface {
	Check(ctx context.Context, spec program.Spec, version, installDir string) error
}

// Installer installs into temporary destination and moves to correct one after
// successful finish.
type Installer struct {
	installer embeddedInstaller
	checker   embeddedChecker
	wg        sync.WaitGroup
}

// NewInstaller creates a new AtomicInstaller
func NewInstaller(i embeddedInstaller, ch embeddedChecker) (*Installer, error) {
	return &Installer{
		installer: i,
		checker:   ch,
	}, nil
}

// Wait allows caller to wait for install to be finished
func (i *Installer) Wait() {
	i.wg.Wait()
}

// Install performs installation of program in a specific version.
func (i *Installer) Install(ctx context.Context, spec program.Spec, version, installDir string) error {
	i.wg.Add(1)
	defer i.wg.Done()

	return i.installer.Install(ctx, spec, version, installDir)
}

// Check performs installation checks
func (i *Installer) Check(ctx context.Context, spec program.Spec, version, installDir string) error {
	i.wg.Add(1)
	defer i.wg.Done()

	return i.checker.Check(ctx, spec, version, installDir)
}
