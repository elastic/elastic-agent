// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package cmd

import (
	"fmt"

	"gopkg.in/ini.v1"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/kardianos/service"
)

func ensureServiceConfigUpToDate() error {
	switch service.ChosenSystem().String() {
	case "linux-systemd":
		unitFilePath := "/etc/systemd/system/" + paths.ServiceName + ".service"
		return ensureSystemdServiceConfigUpToDate(unitFilePath)
	}

	return nil
}

func ensureSystemdServiceConfigUpToDate(unitFilePath string) error {
	cfg, err := ini.Load(unitFilePath)
	if err != nil {
		return fmt.Errorf("error opening systemd unit file [%s]: %w", unitFilePath, err)
	}

	// Check if KillMode= is already present
	if cfg.Section("Service").HasKey("KillMode") {
		// Nothing more to do
		return nil
	}

	// If KillMode= is not present, add it and set it to "process"
	// See https://github.com/elastic/elastic-agent/pull/3220
	cfg.Section("Service").Key("KillMode").SetValue("process")
	if err := cfg.SaveTo(unitFilePath); err != nil {
		return fmt.Errorf("error writing updated systemd unit file [%s]: %w", unitFilePath, err)
	}

	return nil
}
