// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/kardianos/service"
	"gopkg.in/ini.v1"
	"howett.net/plist"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	// ServiceDescription is the description for the service.
	ServiceDescription = "Elastic Agent is a unified agent to observe, monitor and protect your system."

	// Set the launch daemon ExitTimeOut to 60 seconds in order to allow the agent to shutdown gracefully
	// At the moment the version 8.3 & 8.4 of the agent are taking about 11 secs to shutdown
	// and the launchd sends SIGKILL after 5 secs which causes the beats processes to be left running orphaned
	// depending on the shutdown timing.
	darwinServiceExitTimeout = 60

	SystemdUserNameKey  = "User"
	SystemdGroupNameKey = "Group"

	LaunchdUserNameKey  = "UserName"
	LaunchdGroupNameKey = "GroupName"
)

var ErrChangeUserUnsupported = errors.New("ChangeUser is not supported on this system")

// ChangeUser changes user in service definition file directly. In case username or groupName are not provided defaults are used.
func ChangeUser(topPath string, ownership utils.FileOwner, username string, groupName string, password string) error {
	serviceOptions, err := withServiceOptions(username, groupName, password)
	if err != nil {
		return fmt.Errorf("failed to create user info: %w", err)
	}

	opts := serviceOpts{
		Username: username,
		Group:    groupName,
		Password: password,
	}

	for _, o := range serviceOptions {
		o(&opts)
	}

	return changeUser(topPath, ownership, opts.Username, opts.Group, opts.Password)
}

// ExecutablePath returns the path for the installed Agents executable.
func ExecutablePath(topPath string) string {
	exec := filepath.Join(topPath, paths.BinaryName)
	if paths.ShellWrapperPath() != "" {
		exec = paths.ShellWrapperPath()
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
		Name:             paths.ServiceName(),
		DisplayName:      paths.ServiceDisplayName(),
		Description:      ServiceDescription,
		Executable:       ExecutablePath(topPath),
		WorkingDirectory: topPath,
		UserName:         opts.Username,
		Option:           option,
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
		cfg.Option["StandardOutPath"] = filepath.Join(topPath, fmt.Sprintf("%s.out.log", paths.ServiceName()))
		cfg.Option["StandardErrorPath"] = filepath.Join(topPath, fmt.Sprintf("%s.err.log", paths.ServiceName()))
	}

	return service.New(nil, cfg)
}

func changeSystemdServiceFile(serviceName string, serviceFilePath string, username string, groupName string) error {
	svcCfg, err := ini.Load(serviceFilePath)
	if err != nil {
		return fmt.Errorf("failed to read service file %s: %w", serviceFilePath, err)
	}

	ini.PrettyFormat = false
	serviceSection := svcCfg.Section("Service")
	if username != "" {
		if serviceSection.HasKey(SystemdUserNameKey) {
			serviceSection.Key(SystemdUserNameKey).SetValue(username)
		} else {
			_, err := serviceSection.NewKey(SystemdUserNameKey, username)
			if err != nil {
				return fmt.Errorf("failed to update username: %w", err)
			}
		}
	} else if serviceSection.HasKey(SystemdUserNameKey) {
		serviceSection.DeleteKey(SystemdUserNameKey)
	}

	if groupName != "" {
		if serviceSection.HasKey(SystemdGroupNameKey) {
			serviceSection.Key(SystemdGroupNameKey).SetValue(groupName)
		} else {
			_, err := serviceSection.NewKey(SystemdGroupNameKey, groupName)
			if err != nil {
				return fmt.Errorf("failed to update groupName: %w", err)
			}
		}
	} else if serviceSection.HasKey(SystemdGroupNameKey) {
		serviceSection.DeleteKey(SystemdGroupNameKey)
	}

	fileWriter, err := os.OpenFile(serviceFilePath, os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to access service file at %q: %w", serviceFilePath, err)
	}
	defer func() { _ = fileWriter.Close() }()

	if _, err := svcCfg.WriteTo(fileWriter); err != nil {
		return fmt.Errorf("failed to write service file %s: %w", serviceFilePath, err)
	}

	return nil
}

func changeLaunchdServiceFile(serviceName string, plistPath string, username string, groupName string) error {

	// Read the existing plist file
	content, err := os.ReadFile(plistPath)
	if err != nil {
		return fmt.Errorf("failed to read plist file %s: %w", plistPath, err)
	}

	// parser implementation
	dec := plist.NewDecoder(bytes.NewReader(content))
	plistMap := make(map[string]interface{})

	err = dec.Decode(&plistMap)
	if err != nil {
		return fmt.Errorf("failed to decode service file: %w", err)
	}

	if username != "" {
		plistMap[LaunchdUserNameKey] = username
	} else {
		delete(plistMap, LaunchdUserNameKey)
	}

	if groupName != "" {
		plistMap[LaunchdGroupNameKey] = groupName
	} else {
		delete(plistMap, LaunchdGroupNameKey)
	}

	fileWriter, err := os.OpenFile(plistPath, os.O_RDWR|os.O_TRUNC, 0644)
	defer func() { _ = fileWriter.Close() }()

	enc := plist.NewEncoder(fileWriter)
	if err := enc.Encode(plistMap); err != nil {
		return fmt.Errorf("failed to encode service file: %w", err)
	}

	return nil
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
