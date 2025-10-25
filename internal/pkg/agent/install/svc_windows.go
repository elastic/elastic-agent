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

// GetDesiredUser retrieves user and group names as configured in a service file
// on windows it is a no-op
func GetDesiredUser() (string, string, error) { return "", "", nil }

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
	defer func() { _ = m.Disconnect() }()

	serviceName := paths.ServiceName()
	svc, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("failed to open windows service %q: %w", serviceName, err)
	}
	defer svc.Close()

	// always read current config first and then apply modifications to it.
	// it does not work in a way PS sc edit works where it's enough to apply
	// modifications only.
	// beware that due to bug (or way of implementation) in x/sys empty string
	// does not mean empty string but nil, hence no change in value.
	// default values for integers does not result in nil (and no change action) but in invalid values.
	// we don't support empty password for custom user and for system user it should
	// ignore password setting so this should be fine.
	curCfg, err := svc.Config()
	if err != nil {
		return fmt.Errorf("failed to retrieve current service config: %w", err)
	}

	curCfg.ServiceStartName = serviceStartName(username)
	curCfg.Password = servicePassword(username, password)

	err = svc.UpdateConfig(curCfg)
	if err != nil {
		return fmt.Errorf("failed to update config from %v: %w", curCfg, err)
	}

	err = serviceConfigure(ownership)
	if err != nil {
		return fmt.Errorf("failed to configure service (%s) from %v: %w", paths.ServiceName(), curCfg, err)
	}

	return nil
}

func serviceStartName(username string) string {
	if len(username) == 0 {
		return `.\LocalSystem`
	}

	return username
}

func servicePassword(username, password string) string {
	if len(username) == 0 {
		// in case of LocalSystem password should be ignored,
		// reset to empty string just to be sure
		return ""
	}
	return password
}
