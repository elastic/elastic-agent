// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"path/filepath"
	"runtime"

	"github.com/kardianos/service"

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
func ExecutablePath() string {
	exec := filepath.Join(paths.InstallPath, paths.BinaryName)
	if paths.ShellWrapperPath != "" {
		exec = paths.ShellWrapperPath
	}
	return exec
}

func newService() (service.Service, error) {
	cfg := &service.Config{
		Name:             paths.ServiceName,
		DisplayName:      ServiceDisplayName,
		Description:      ServiceDescription,
		Executable:       ExecutablePath(),
		WorkingDirectory: paths.InstallPath,
		Option: map[string]interface{}{
			// Linux (systemd) always restart on failure
			"Restart": "always",

			// Windows setup restart on failure
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "1s",
			"OnFailureResetPeriod":   10,
		},
	}

	if runtime.GOOS == "darwin" {
		// The github.com/kardianos/service library doesn't support ExitTimeOut in their prebuilt template.
		// This option allows to pass our own template for the launch daemon plist, which is a copy
		// of the prebuilt template with added ExitTimeOut option
		cfg.Option["LaunchdConfig"] = darwinLaunchdConfig
		cfg.Option["ExitTimeOut"] = darwinServiceExitTimeout
	}

	return service.New(nil, cfg)
}

// A copy of the launchd plist template from github.com/kardianos/service
// with added .Config.Option.ExitTimeOut option
const darwinLaunchdConfig = `<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd" >
<plist version='1.0'>
  <dict>
    <key>Label</key>
    <string>{{html .Name}}</string>
    <key>ProgramArguments</key>
    <array>
      <string>{{html .Path}}</string>
    {{range .Config.Arguments}}
      <string>{{html .}}</string>
    {{end}}
    </array>
    {{if .UserName}}<key>UserName</key>
    <string>{{html .UserName}}</string>{{end}}
    {{if .ChRoot}}<key>RootDirectory</key>
    <string>{{html .ChRoot}}</string>{{end}}
    {{if .Config.Option.ExitTimeOut}}<key>ExitTimeOut</key>
    <integer>{{html .Config.Option.ExitTimeOut}}</integer>{{end}}
    {{if .WorkingDirectory}}<key>WorkingDirectory</key>
    <string>{{html .WorkingDirectory}}</string>{{end}}
    <key>SessionCreate</key>
    <{{bool .SessionCreate}}/>
    <key>KeepAlive</key>
    <{{bool .KeepAlive}}/>
    <key>RunAtLoad</key>
    <{{bool .RunAtLoad}}/>
    <key>Disabled</key>
    <false/>

    <key>StandardOutPath</key>
    <string>/usr/local/var/log/{{html .Name}}.out.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/{{html .Name}}.err.log</string>

  </dict>
</plist>
`
