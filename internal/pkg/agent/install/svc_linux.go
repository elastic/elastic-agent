// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux

package install

import (
	"fmt"
	"os"
	"os/exec"

	"gopkg.in/ini.v1"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// GetDesiredUser retrieves user and group names as configured in a service file
func GetDesiredUser() (string, string, error) {
	serviceFilePath := fmt.Sprintf("/etc/systemd/system/%s.service", paths.ServiceName())
	svcCfg, err := ini.Load(serviceFilePath)
	if os.IsNotExist(err) {
		// not running as a service
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("failed to read service file %s: %w", serviceFilePath, err)
	}

	var username, groupname string

	serviceSection := svcCfg.Section("Service")
	if serviceSection.HasKey(SystemdUserNameKey) {
		username = serviceSection.Key(SystemdUserNameKey).Value()
	}

	if serviceSection.HasKey(SystemdGroupNameKey) {
		groupname = serviceSection.Key(SystemdGroupNameKey).Value()
	}

	return username, groupname, nil
}

// changeUser changes user associated with a service without reinstalling the service itself
func changeUser(topPath string, ownership utils.FileOwner, username string, groupName string, _ string) error {
	if !isSystemdRunning() {
		return ErrChangeUserUnsupported
	}

	serviceName := paths.ServiceName()
	serviceFilePath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)

	if err := changeSystemdServiceFile(serviceName, serviceFilePath, username, groupName); err != nil {
		return err
	}

	// Reload systemd daemon to pick up changes
	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	return nil
}

// isSystemdRunning checks if systemd is the init system and is running
func isSystemdRunning() bool {
	// Check if systemd is PID 1
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return true
	}

	// Alternative check: see if systemctl command exists and works
	cmd := exec.Command("systemctl", "is-system-running")
	if err := cmd.Run(); err == nil {
		return true
	}

	// Check if /proc/1/comm contains systemd
	if data, err := os.ReadFile("/proc/1/comm"); err == nil {
		return string(data) == "systemd\n"
	}

	return false
}
