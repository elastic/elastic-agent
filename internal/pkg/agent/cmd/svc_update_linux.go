// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package cmd

import (
	"fmt"
	"os/exec"

	"gopkg.in/ini.v1"

	"github.com/kardianos/service"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

func ensureServiceConfigUpToDate() error {
	switch service.ChosenSystem().String() {
	case "linux-systemd":
		unitFilePath := "/etc/systemd/system/" + paths.ServiceName + ".service"
		if err := ensureSystemdServiceConfigUpToDate(unitFilePath); err != nil {
			return err
		}

		// Reload systemd unit configuration files
		cmd := exec.Command("systemctl", "daemon-reload")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("error reloading systemd unit configuration files: %w", err)
		}

	}

	return nil
}

func ensureSystemdServiceConfigUpToDate(unitFilePath string) error {
	// It is safe to use an INI file parser/writer for systemd unit files.
	// See https://www.freedesktop.org/software/systemd/man/systemd.syntax.html
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
