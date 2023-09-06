// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package upgrade

import (
	"fmt"
	"os/exec"

	"gopkg.in/ini.v1"

	"github.com/kardianos/service"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

// EnsureServiceConfigUpToDate modifies, if necessary, Elastic Agent's service
// configuration file to its latest definition. This change is NOT rolled back
// if the Agent is rolled back to a previous version.
func EnsureServiceConfigUpToDate() error {
	switch service.ChosenSystem().String() {
	case "linux-systemd":
		unitFilePath := "/etc/systemd/system/" + paths.ServiceName + ".service"
		updated, err := ensureSystemdServiceConfigUpToDate(unitFilePath)
		if err != nil {
			return err
		}

		if !updated {
			// Nothing more to do!
			return nil
		}

		// Reload systemd unit configuration files
		cmd := exec.Command("systemctl", "daemon-reload")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("error reloading systemd unit configuration files: %w", err)
		}

	}

	return nil
}

// ensureSystemdServiceConfigUpToDate modifies, if necessary, Elastic Agent's systemd
// unit configuration file to its latest definition. If the the file is modified, this
// function returns true; otherwise, it returns false.
func ensureSystemdServiceConfigUpToDate(unitFilePath string) (bool, error) {
	// It is safe to use an INI file parser/writer for systemd unit files.
	// See https://www.freedesktop.org/software/systemd/man/systemd.syntax.html
	cfg, err := ini.Load(unitFilePath)
	if err != nil {
		return false, fmt.Errorf("error opening systemd unit file [%s]: %w", unitFilePath, err)
	}

	// Check if KillMode= is already present
	if cfg.Section("Service").HasKey("KillMode") {
		// Nothing more to do
		return false, nil
	}

	// If KillMode= is not present, add it and set it to "process"
	// See https://github.com/elastic/elastic-agent/pull/3220
	cfg.Section("Service").Key("KillMode").SetValue("process")
	if err := cfg.SaveTo(unitFilePath); err != nil {
		return false, fmt.Errorf("error writing updated systemd unit file [%s]: %w", unitFilePath, err)
	}

	return true, nil
}
