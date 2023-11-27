// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"fmt"
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

	cfg := &service.Config{
		Name:             paths.ServiceName,
		DisplayName:      ServiceDisplayName,
		Description:      ServiceDescription,
		Executable:       ExecutablePath(topPath),
		WorkingDirectory: topPath,
		UserName:         opts.Username,
		Option: map[string]interface{}{
			// GroupName
			"GroupName": opts.Group,

			// Linux (systemd) always restart on failure
			"Restart": "always",

			// Windows setup restart on failure
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "15s", // Matches the value used by endpoint-security.
			"OnFailureResetPeriod":   10,
		},
	}

	if runtime.GOOS == "linux" {
		// The github.com/kardianos/service library doesn't support KillMode in their prebuilt template.
		// This option allows to pass our own template for the systemd unit configuration, which is a copy
		// of the prebuilt template with added KillMode option
		cfg.Option["SystemdScript"] = linuxSystemdScript

		// By setting KillMode=process in Elastic Agent's systemd unit configuration file, we ensure
		// that in a scenario where the upgraded Agent's process is repeatedly crashing, systemd keeps
		// the Upgrade Watcher process running so it can monitor the Agent process for long enough to
		// initiate a rollback.
		// See also https://github.com/elastic/elastic-agent/pull/3220#issuecomment-1673935694.
		cfg.Option["KillMode"] = "process"
	}

	if runtime.GOOS == "darwin" {
		// The github.com/kardianos/service library doesn't support ExitTimeOut in their prebuilt template.
		// This option allows to pass our own template for the launch daemon plist, which is a copy
		// of the prebuilt template with added ExitTimeOut option
		cfg.Option["LaunchdConfig"] = darwinLaunchdConfig
		cfg.Option["ExitTimeOut"] = darwinServiceExitTimeout

		// Set the stdout and stderr logs to be inside the installation directory, ensures that the
		// executing user for the service can write to the directory for the logs.
		cfg.Option["StandardOutPath"] = filepath.Join(topPath, fmt.Sprintf("%s.out.log", paths.ServiceName))
		cfg.Option["StandardErrorPath"] = filepath.Join(topPath, fmt.Sprintf("%s.err.log", paths.ServiceName))
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
	{{if .Config.Option.GroupName -}}
	<key>GroupName</key>
    <string>{{html .Config.Option.GroupName}}</string>
	{{- end}}
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
    <string>{{html .Config.Option.StandardOutPath}}</string>
    <key>StandardErrorPath</key>
    <string>{{html .Config.Option.StandardErrorPath}}</string>

  </dict>
</plist>
`

// A copy of the systemd config template from github.com/kardianos/service
// with added .Config.Option.KillMode option
const linuxSystemdScript = `[Unit]
Description={{.Description}}
ConditionFileIsExecutable={{.Path|cmdEscape}}
{{range $i, $dep := .Dependencies}}
{{$dep}} {{end}}

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart={{.Path|cmdEscape}}{{range .Arguments}} {{.|cmd}}{{end}}
{{if .ChRoot}}RootDirectory={{.ChRoot|cmd}}{{end}}
{{if .WorkingDirectory}}WorkingDirectory={{.WorkingDirectory|cmdEscape}}{{end}}
{{if .UserName}}User={{.UserName}}{{end}}
{{if .Config.Option.GroupName -}}
Group={{.Config.Option.GroupName}}
{{- end}}
{{if .ReloadSignal}}ExecReload=/bin/kill -{{.ReloadSignal}} "$MAINPID"{{end}}
{{if .PIDFile}}PIDFile={{.PIDFile|cmd}}{{end}}
{{if and .LogOutput .HasOutputFileSupport -}}
StandardOutput=file:/var/log/{{.Name}}.out
StandardError=file:/var/log/{{.Name}}.err
{{- end}}
{{if gt .LimitNOFILE -1 }}LimitNOFILE={{.LimitNOFILE}}{{end}}
{{if .Restart}}Restart={{.Restart}}{{end}}
{{if .SuccessExitStatus}}SuccessExitStatus={{.SuccessExitStatus}}{{end}}
{{if .Config.Option.KillMode}}KillMode={{.Config.Option.KillMode}}{{end}}
RestartSec=120
EnvironmentFile=-/etc/sysconfig/{{.Name}}

[Install]
WantedBy=multi-user.target
`
