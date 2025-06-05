// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package install

import (
	"fmt"

	"golang.org/x/sys/windows/svc/mgr"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func withPassword(password string) serviceOpt {
	return func(opts *serviceOpts) {
		opts.Password = password
	}
}

// changeUser changes user associated with a service without reinstalling the service itself
func changeUser(topPath string, ownership utils.FileOwner, username string, groupName string, password string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to windows service manager: %w", err)
	}
	defer m.Disconnect()

	serviceName := paths.ServiceName()
	svc, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("failed to open windows service %q: %w", serviceName, err)
	}
	defer svc.Close()

	cfg := mgr.Config{
		ServiceStartName: serviceStartName(username),
		Password:         password,
	}

	err = svc.UpdateConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	err = serviceConfigure(ownership)
	if err != nil {
		return fmt.Errorf("failed to configure service (%s): %w", paths.ServiceName(), err)
	}

	return nil
}

func serviceStartName(username string) string {
	if username == "" {
		return "LocalSystem"
	}

	return username
}
