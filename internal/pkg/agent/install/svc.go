// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"path/filepath"
	"runtime"

	"github.com/elastic/go-service"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

const (
	// ServiceDisplayName is the service display name for the service.
	ServiceDisplayName = "Elastic Agent"

	// ServiceDescription is the description for the service.
	ServiceDescription = "Elastic Agent is a unified agent to observe, monitor and protect your system."

	// Set the launch daemon ExitTimeOut to 60 seconds in order to allow the agent to shutdown gracefully
	// At the moment the version 8.3 & 8.4 of the agent are taking about 11 secs to shutdown
	// and the launchd sends SIGKILL after 5 secs which causes the beats processes to be left running orphaned
	// depending on the shutdown timing.
	darwinServiceExitTimeout = 60
)

// ExecutablePath returns the path for the installed Agents executable.
func ExecutablePath(topPath string) string {
	exec := filepath.Join(topPath, paths.BinaryName)
	if paths.ShellWrapperPath != "" {
		exec = paths.ShellWrapperPath
	}
	return exec
}

type serviceOpts struct {
	Username string
	Group    string
	Password string
}

type serviceOpt func(opts *serviceOpts)

func withUserGroup(username string, group string) serviceOpt {
	return func(opts *serviceOpts) {
		opts.Username = username
		opts.Group = group
	}
}

func newService(topPath string, opt ...serviceOpt) (service.Service, error) {
	var opts serviceOpts
	for _, o := range opt {
		o(&opts)
	}

	option := map[string]interface{}{
		// GroupName
		"GroupName": opts.Group,

		// Linux (systemd) always restart on failure
		"Restart": "always",

		// Windows setup restart on failure
		"OnFailure":              "restart",
		"OnFailureDelayDuration": "15s", // Matches the value used by endpoint-security.
		"OnFailureResetPeriod":   10,
	}
	if opts.Password != "" {
		option["Password"] = opts.Password
	}

	cfg := &service.Config{
		Name:             paths.ServiceName,
		DisplayName:      ServiceDisplayName,
		Description:      ServiceDescription,
		Executable:       ExecutablePath(topPath),
		WorkingDirectory: topPath,
		UserName:         opts.Username,
		Option:           option,
	}

	if runtime.GOOS == "linux" {
		// By setting KillMode=process in Elastic Agent's systemd unit configuration file, we ensure
		// that in a scenario where the upgraded Agent's process is repeatedly crashing, systemd keeps
		// the Upgrade Watcher process running so it can monitor the Agent process for long enough to
		// initiate a rollback.
		// See also https://github.com/elastic/elastic-agent/pull/3220#issuecomment-1673935694.
		cfg.Option["KillMode"] = "process"
	}

	if runtime.GOOS == "darwin" {
		cfg.Option["ExitTimeOut"] = darwinServiceExitTimeout

		// Set log directory to be inside the installation directory, ensures that the
		// executing user for the service can write to the directory for the logs.
		cfg.Option["LogDirectory"] = topPath
	}

	return service.New(nil, cfg)
}
