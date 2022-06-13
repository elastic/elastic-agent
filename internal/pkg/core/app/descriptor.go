// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package app

import (
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/artifact"
	"github.com/elastic/elastic-agent/pkg/component"
)

// Descriptor defines a program which needs to be run.
// Is passed around operator operations.
type Descriptor struct {
	spec         component.Spec
	executionCtx ExecutionContext
	directory    string
	process      ProcessSpec
}

// NewDescriptor creates a program which satisfies Program interface and can be used with Operator.
func NewDescriptor(spec component.Spec, version string, config *artifact.Config, tags map[Tag]string) *Descriptor {
	dir := paths.Components()
	return NewDescriptorWithPath(dir, spec, version, config, tags)
}

// NewDescriptorOnPath creates a program which satisfies Program interface and can be used with Operator.
func NewDescriptorWithPath(path string, spec component.Spec, version string, config *artifact.Config, tags map[Tag]string) *Descriptor {
	servicePort := 0
	if spec.ProgramSpec.ServicePort > 0 {
		servicePort = spec.ProgramSpec.ServicePort
	}

	return &Descriptor{
		spec:         spec,
		directory:    path,
		executionCtx: NewExecutionContext(servicePort, spec.CommandName(), version, tags),
		process:      specification(path, spec),
	}
}

// ServicePort is the port the service will connect to gather GRPC information. When this is not
// 0 then the application is ran using the `service` application type, versus a `process` application.
func (p *Descriptor) ServicePort() int {
	return p.executionCtx.ServicePort
}

// BinaryName is the name of the binary. E.g filebeat.
func (p *Descriptor) BinaryName() string {
	return p.executionCtx.BinaryName
}

// Version specifies a version of the applications e.g '7.2.0'.
func (p *Descriptor) Version() string { return p.executionCtx.Version }

// Tags is a collection of tags used to specify application more precisely.
// Two descriptor with same binary name and version but with different tags will
// result in two different instances of the application.
func (p *Descriptor) Tags() map[Tag]string { return p.executionCtx.Tags }

// ID is a unique representation of the application.
func (p *Descriptor) ID() string { return p.executionCtx.ID }

// ExecutionContext returns execution context of the application.
func (p *Descriptor) ExecutionContext() ExecutionContext { return p.executionCtx }

// Spec returns a program specification with resolved binary path.
func (p *Descriptor) Spec() component.Spec {
	return p.spec
}

// ProcessSpec returns a process specification with resolved binary path.
func (p *Descriptor) ProcessSpec() ProcessSpec {
	return p.process
}

// Directory specifies the root directory of the application within an install path.
func (p *Descriptor) Directory() string {
	return p.directory
}

func specification(dir string, spec component.Spec) ProcessSpec {
	return ProcessSpec{
		BinaryPath:    filepath.Join(dir, spec.Command()),
		Args:          spec.Args(),
		Configuration: nil,
	}
}
