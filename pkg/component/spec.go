// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"errors"
	"fmt"
	"time"
)

// Spec a components specification.
type Spec struct {
	Version  int           `config:"version" yaml:"version" validate:"required"`
	Inputs   []InputSpec   `config:"inputs,omitempty" yaml:"inputs,omitempty"`
	Shippers []ShipperSpec `config:"shippers,omitempty" yaml:"shippers,omitempty"`
}

// Validate ensures correctness of component specification.
func (s *Spec) Validate() error {
	if s.Version != 2 {
		return errors.New("only version 2 is allowed")
	}
	inputsToPlatforms := make(map[string][]string)
	for i, input := range s.Inputs {
		a, ok := inputsToPlatforms[input.Name]
		if !ok {
			inputsToPlatforms[input.Name] = make([]string, len(input.Platforms))
			copy(inputsToPlatforms[input.Name], input.Platforms)
			continue
		}
		for _, platform := range input.Platforms {
			for _, existing := range a {
				if existing == platform {
					return fmt.Errorf("input '%s' at inputs.%d defines the same platform as a previous definition", input.Name, i)
				}
			}
			a = append(a, platform)
			inputsToPlatforms[input.Name] = a
		}
	}
	shippersToPlatforms := make(map[string][]string)
	for i, shipper := range s.Shippers {
		a, ok := shippersToPlatforms[shipper.Name]
		if !ok {
			shippersToPlatforms[shipper.Name] = make([]string, len(shipper.Platforms))
			copy(shippersToPlatforms[shipper.Name], shipper.Platforms)
			continue
		}
		for _, platform := range shipper.Platforms {
			for _, existing := range a {
				if existing == platform {
					return fmt.Errorf("shipper '%s' at shippers.%d defines the same platform as a previous definition", shipper.Name, i)
				}
			}
			a = append(a, platform)
			shippersToPlatforms[shipper.Name] = a
		}
	}
	return nil
}

// RuntimeSpec is the specification for runtime options.
type RuntimeSpec struct {
	Preventions []RuntimePreventionSpec `config:"preventions,omitempty" yaml:"preventions,omitempty"`
}

// RuntimePreventionSpec is the specification that prevents an input to run at execution time.
type RuntimePreventionSpec struct {
	Condition string `config:"condition" yaml:"condition" validate:"required"`
	Message   string `config:"message" yaml:"message" validate:"required"`
}

// CommandSpec is the specification for an input that executes as a subprocess.
type CommandSpec struct {
	Args                    []string           `config:"args,omitempty" yaml:"args,omitempty"`
	Env                     []CommandEnvSpec   `config:"env,omitempty" yaml:"env,omitempty"`
	Timeouts                CommandTimeoutSpec `config:"timeouts,omitempty" yaml:"timeouts,omitempty"`
	Log                     CommandLogSpec     `config:"log,omitempty" yaml:"log,omitempty"`
	RestartMonitoringPeriod time.Duration      `config:"restart_monitoring_period,omitempty" yaml:"restart_monitoring_period,omitempty"`
	MaxRestartsPerPeriod    int                `config:"maximum_restarts_per_period,omitempty" yaml:"maximum_restarts_per_period,omitempty"`
}

// CommandEnvSpec is the specification that defines environment variables that will be set to execute the subprocess.
type CommandEnvSpec struct {
	Name  string `config:"name" yaml:"name" validate:"required"`
	Value string `config:"value" yaml:"value" validate:"required"`
}

// CommandTimeoutSpec is the timeout specification for subprocess.
type CommandTimeoutSpec struct {
	Checkin time.Duration `config:"checkin,omitempty" yaml:"checkin,omitempty"`
	Restart time.Duration `config:"restart,omitempty" yaml:"restart,omitempty"`
	Stop    time.Duration `config:"stop,omitempty" yaml:"stop,omitempty"`
}

// InitDefaults initialized the defaults for the timeouts.
func (t *CommandTimeoutSpec) InitDefaults() {
	t.Checkin = 30 * time.Second
	t.Restart = 10 * time.Second
	t.Stop = 30 * time.Second
}

// CommandLogSpec is the log specification for subprocess.
type CommandLogSpec struct {
	LevelKey   string   `config:"level_key,omitempty" yaml:"level_key,omitempty"`
	TimeKey    string   `config:"time_key,omitempty" yaml:"time_key,omitempty"`
	TimeFormat string   `config:"time_format,omitempty" yaml:"time_format,omitempty"`
	MessageKey string   `config:"message_key,omitempty" yaml:"message_key,omitempty"`
	IgnoreKeys []string `config:"ignore_keys,omitempty" yaml:"ignore_keys,omitempty"`
}

// InitDefaults initialized the defaults for the timeouts.
func (t *CommandLogSpec) InitDefaults() {
	t.LevelKey = "log.level"
	t.TimeKey = "@timestamp"
	t.TimeFormat = "2006-01-02T15:04:05.000Z0700"
	t.MessageKey = "message"
}

// ServiceTimeoutSpec is the timeout specification for subprocess.
type ServiceTimeoutSpec struct {
	Checkin time.Duration `config:"checkin,omitempty" yaml:"checkin,omitempty"`
}

// InitDefaults initialized the defaults for the timeouts.
func (t *ServiceTimeoutSpec) InitDefaults() {
	t.Checkin = 30 * time.Second
}

// ServiceSpec is the specification for an input that executes as a service.
type ServiceSpec struct {
	CPort      int                   `config:"cport" yaml:"cport" validate:"required"`
	Log        *ServiceLogSpec       `config:"log,omitempty" yaml:"log,omitempty"`
	Operations ServiceOperationsSpec `config:"operations" yaml:"operations" validate:"required"`
	Timeouts   ServiceTimeoutSpec    `config:"timeouts,omitempty" yaml:"timeouts,omitempty"`
}

// ServiceLogSpec is the specification for the log path that the service logs to.
type ServiceLogSpec struct {
	Path string `config:"path,omitempty" yaml:"path,omitempty"`
}

// ServiceOperationsSpec is the specification of the operations that need to be performed to get a service installed/uninstalled.
type ServiceOperationsSpec struct {
	Check     *ServiceOperationsCommandSpec `config:"check,omitempty" yaml:"check,omitempty"`
	Install   *ServiceOperationsCommandSpec `config:"install" yaml:"install" validate:"required"`
	Uninstall *ServiceOperationsCommandSpec `config:"uninstall" yaml:"uninstall" validate:"required"`
}

// ServiceOperationsCommandSpec is the specification for execution of binaries to perform the check, install, and uninstall.
type ServiceOperationsCommandSpec struct {
	Args    []string         `config:"args,omitempty" yaml:"args,omitempty"`
	Env     []CommandEnvSpec `config:"env,omitempty" yaml:"env,omitempty"`
	Timeout time.Duration    `config:"timeout,omitempty" yaml:"timeout,omitempty"`
	Retry   RetryConfig
}

type RetryConfig struct {
	InitInterval time.Duration `config:"init_interval,omitempty" yaml:"init_interval,omitempty"`
}
