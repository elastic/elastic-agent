// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/kardianos/service"

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
	// Read the existing service file
	content, err := os.ReadFile(serviceFilePath)
	if err != nil {
		return fmt.Errorf("failed to read service file %s: %w", serviceFilePath, err)
	}

	lines := strings.Split(string(content), "\n")
	var modifiedLines []string
	userSet := false
	groupSet := false
	inServiceSection := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Check if we're in the [Service] section
		if strings.HasPrefix(trimmedLine, "[Service]") {
			inServiceSection = true
			modifiedLines = append(modifiedLines, line)
			continue
		} else if strings.HasPrefix(trimmedLine, "[") {
			// We've entered a different section
			if inServiceSection && !userSet {
				// Add User before leaving Service section
				modifiedLines = append(modifiedLines, fmt.Sprintf("User=%s", username))
				userSet = true
			}
			if inServiceSection && !groupSet && groupName != "" {
				// Add Group before leaving Service section
				modifiedLines = append(modifiedLines, fmt.Sprintf("Group=%s", groupName))
				groupSet = true
			}
			inServiceSection = false
			modifiedLines = append(modifiedLines, line)
			continue
		}

		if inServiceSection {
			// Replace existing User or Group definitions
			if strings.HasPrefix(trimmedLine, "User=") {
				if username != "" {
					modifiedLines = append(modifiedLines, fmt.Sprintf("User=%s", username))
				}
				userSet = true // mark so it is not added at the end
				continue
			}
			if strings.HasPrefix(trimmedLine, "Group=") {
				if groupName != "" {
					modifiedLines = append(modifiedLines, fmt.Sprintf("Group=%s", groupName))
				}
				groupSet = true // mark so it is not added at the end
				continue
			}
		}

		// include rest of the definition
		modifiedLines = append(modifiedLines, line)
	}

	// If we never found User/Group in Service section, add them at the end
	if !userSet || (!groupSet && groupName != "") {
		// Find the last line of the Service section and add User/Group there
		for i := len(modifiedLines) - 1; i >= 0; i-- {
			if strings.TrimSpace(modifiedLines[i]) == "[Service]" {
				insertPos := i + 1
				if !userSet {
					modifiedLines = append(modifiedLines[:insertPos], append([]string{fmt.Sprintf("User=%s", username)}, modifiedLines[insertPos:]...)...)
					insertPos++
				}
				if !groupSet && groupName != "" {
					modifiedLines = append(modifiedLines[:insertPos], append([]string{fmt.Sprintf("Group=%s", groupName)}, modifiedLines[insertPos:]...)...)
				}
				break
			}
		}
	}

	// Write the modified content back to the service file
	modifiedContent := strings.Join(modifiedLines, "\n")
	if err := os.WriteFile(serviceFilePath, []byte(modifiedContent), 0644); err != nil {
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

	contentStr := string(content)

	if username != "" {
		// Update or add UserName
		userNameRegex := regexp.MustCompile(`(?s)<key>UserName</key>\s*<string>[^<]*</string>`)
		userNameReplacement := fmt.Sprintf("<key>UserName</key>\n    <string>%s</string>", username)

		if userNameRegex.MatchString(contentStr) {
			// Replace existing UserName
			contentStr = userNameRegex.ReplaceAllString(contentStr, userNameReplacement)
		} else {
			// Add UserName after ProgramArguments array
			progArgsEndRegex := regexp.MustCompile(`(?s)</array>`)
			matches := progArgsEndRegex.FindAllStringIndex(contentStr, -1)
			if len(matches) > 0 {
				// Insert after the first </array> (ProgramArguments)
				insertPos := matches[0][1]
				contentStr = contentStr[:insertPos] + "\n    " + userNameReplacement + contentStr[insertPos:]
			}
		}
	} else {
		// remove user section
		userNameRegex := regexp.MustCompile(`(?s)\s*<key>UserName</key>\s*<string>[^<]*</string>`)
		contentStr = userNameRegex.ReplaceAllString(contentStr, "")
	}

	// Update or add GroupName if specified
	if groupName != "" {
		groupNameRegex := regexp.MustCompile(`(?s)<key>GroupName</key>\s*<string>[^<]*</string>`)
		groupNameReplacement := fmt.Sprintf("<key>GroupName</key>\n    <string>%s</string>", groupName)

		if groupNameRegex.MatchString(contentStr) {
			// Replace existing GroupName
			contentStr = groupNameRegex.ReplaceAllString(contentStr, groupNameReplacement)
		} else {
			// Add GroupName after UserName
			userNameEndRegex := regexp.MustCompile(`(?s)<key>UserName</key>\s*<string>[^<]*</string>`)
			contentStr = userNameEndRegex.ReplaceAllString(contentStr, "$0\n    "+groupNameReplacement)
		}
	} else {
		// Remove GroupName if it exists and no group is specified
		groupNameRegex := regexp.MustCompile(`(?s)\s*<key>GroupName</key>\s*<string>[^<]*</string>`)
		contentStr = groupNameRegex.ReplaceAllString(contentStr, "")
	}

	// Write the modified content back to the plist file
	if err := os.WriteFile(plistPath, []byte(contentStr), 0644); err != nil {
		return fmt.Errorf("failed to write plist file %s: %w", plistPath, err)
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
