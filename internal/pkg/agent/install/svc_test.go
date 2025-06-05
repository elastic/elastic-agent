// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChangeLaunchdServiceFile(t *testing.T) {
	testCases := []struct {
		name             string
		initialContent   string
		username         string
		groupName        string
		expectedUser     string
		expectedGroup    string
		expectStopCall   bool
		expectReloadCall bool
	}{
		{
			name: "Add user and group to plist without existing UserName/GroupName",
			initialContent: `<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd" >
<plist version='1.0'>
  <dict>
    <key>Label</key>
    <string>co.elastic.elastic-agent</string>
    <key>ProgramArguments</key>
    <array>
      <string>/opt/Elastic/Agent/elastic-agent</string>
    </array>
    <key>SessionCreate</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>`,
			username:         "elastic-agent",
			groupName:        "elastic-agent",
			expectedUser:     "elastic-agent",
			expectedGroup:    "elastic-agent",
			expectStopCall:   true,
			expectReloadCall: true,
		},
		{
			name: "Replace existing user and group in plist",
			initialContent: `<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd" >
<plist version='1.0'>
  <dict>
    <key>Label</key>
    <string>co.elastic.elastic-agent</string>
    <key>ProgramArguments</key>
    <array>
      <string>/opt/Elastic/Agent/elastic-agent</string>
    </array>
    <key>UserName</key>
    <string>olduser</string>
    <key>GroupName</key>
    <string>oldgroup</string>
    <key>SessionCreate</key>
    <true/>
  </dict>
</plist>`,
			username:         "newuser",
			groupName:        "newgroup",
			expectedUser:     "newuser",
			expectedGroup:    "newgroup",
			expectStopCall:   true,
			expectReloadCall: true,
		},
		{
			name: "Add user only, no group specified",
			initialContent: `<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd" >
<plist version='1.0'>
  <dict>
    <key>Label</key>
    <string>co.elastic.elastic-agent</string>
    <key>ProgramArguments</key>
    <array>
      <string>/opt/Elastic/Agent/elastic-agent</string>
    </array>
    <key>SessionCreate</key>
    <true/>
  </dict>
</plist>`,
			username:         "elastic-agent",
			groupName:        "", // No group
			expectedUser:     "elastic-agent",
			expectedGroup:    "", // Should not be present
			expectStopCall:   true,
			expectReloadCall: true,
		},
		{
			name: "Remove existing user when no group specified",
			initialContent: `<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd" >
<plist version='1.0'>
  <dict>
    <key>Label</key>
    <string>co.elastic.elastic-agent</string>
    <key>ProgramArguments</key>
    <array>
      <string>/opt/Elastic/Agent/elastic-agent</string>
    </array>
    <key>UserName</key>
    <string>olduser</string>
    <key>GroupName</key>
    <string>oldgroup</string>
    <key>SessionCreate</key>
    <true/>
  </dict>
</plist>`,
			username:         "", // Remove user
			groupName:        "", // Remove group
			expectedUser:     "", // Should be removed
			expectedGroup:    "", // Should be removed
			expectStopCall:   true,
			expectReloadCall: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a temporary directory and file
			tempDir := t.TempDir()
			plistPath := filepath.Join(tempDir, "test-service.plist")

			// Write initial content to the plist file
			err := os.WriteFile(plistPath, []byte(tc.initialContent), 0644)
			require.NoError(t, err, "Failed to write initial plist file")

			// Track function calls
			var stopCalled, reloadCalled bool
			var stopServiceName, reloadServiceName string

			stopFn := func(serviceName string) error {
				stopCalled = true
				stopServiceName = serviceName
				return nil
			}

			reloadFn := func(serviceName string) error {
				reloadCalled = true
				reloadServiceName = serviceName
				return nil
			}

			// Call the function under test
			serviceName := "test-service"
			err = changeLaunchdServiceFile(serviceName, plistPath, tc.username, tc.groupName, stopFn, reloadFn)
			require.NoError(t, err, "changeLaunchdServiceFile should not return an error")

			// Verify that stop and reload functions were called as expected
			require.Equal(t, tc.expectStopCall, stopCalled, "Stop function call expectation mismatch")
			require.Equal(t, tc.expectReloadCall, reloadCalled, "Reload function call expectation mismatch")

			require.Equal(t, serviceName, stopServiceName, "Stop function called with wrong service name")
			require.Equal(t, serviceName, reloadServiceName, "Reload function called with wrong service name")

			// Read the modified content
			modifiedContent, err := os.ReadFile(plistPath)
			require.NoError(t, err, "Failed to read modified plist file")

			modifiedStr := string(modifiedContent)

			// Verify UserName is set correctly
			if tc.expectedUser != "" {
				require.Contains(t, modifiedStr, "<key>UserName</key>", "UserName key should be present")
				require.Contains(t, modifiedStr, fmt.Sprintf("<string>%s</string>", tc.expectedUser), "UserName value should be correct")

				// Count occurrences to ensure only one UserName entry
				userKeyCount := strings.Count(modifiedStr, "<key>UserName</key>")
				require.Equal(t, 1, userKeyCount, "Should have exactly one UserName key")
			} else {
				require.NotContains(t, modifiedStr, "<key>UserName</key>", "UserName key should not be present when no user is specified")
			}

			// Verify GroupName is set correctly
			if tc.expectedGroup != "" {
				require.Contains(t, modifiedStr, "<key>GroupName</key>", "GroupName key should be present")
				require.Contains(t, modifiedStr, fmt.Sprintf("<string>%s</string>", tc.expectedGroup), "GroupName value should be correct")

				// Count occurrences to ensure only one GroupName entry
				groupKeyCount := strings.Count(modifiedStr, "<key>GroupName</key>")
				require.Equal(t, 1, groupKeyCount, "Should have exactly one GroupName key")
			} else {
				require.NotContains(t, modifiedStr, "<key>GroupName</key>", "GroupName key should not be present when no group specified")
			}

			// Clean up
			err = os.Remove(plistPath)
			require.NoError(t, err, "Failed to clean up plist file")
		})
	}
}

func TestChangeSystemdServiceFile(t *testing.T) {
	testCases := []struct {
		name           string
		initialContent string
		username       string
		groupName      string
		expectedUser   string
		expectedGroup  string
	}{
		{
			name: "Add user and group to service without existing User/Group",
			initialContent: `[Unit]
Description=Elastic Agent
ConditionFileIsExecutable=/opt/Elastic/Agent/elastic-agent

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/opt/Elastic/Agent/elastic-agent
Restart=always
RestartSec=120

[Install]
WantedBy=multi-user.target
`,
			username:      "elastic-agent",
			groupName:     "elastic-agent",
			expectedUser:  "elastic-agent",
			expectedGroup: "elastic-agent",
		},
		{
			name: "Replace existing user and group in service",
			initialContent: `[Unit]
Description=Elastic Agent
ConditionFileIsExecutable=/opt/Elastic/Agent/elastic-agent

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/opt/Elastic/Agent/elastic-agent
User=olduser
Group=oldgroup
Restart=always
RestartSec=120

[Install]
WantedBy=multi-user.target
`,
			username:      "newuser",
			groupName:     "newgroup",
			expectedUser:  "newuser",
			expectedGroup: "newgroup",
		},
		{
			name: "Add user only, no group specified",
			initialContent: `[Unit]
Description=Elastic Agent
ConditionFileIsExecutable=/opt/Elastic/Agent/elastic-agent

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/opt/Elastic/Agent/elastic-agent
Restart=always
RestartSec=120

[Install]
WantedBy=multi-user.target
`,
			username:      "elastic-agent",
			groupName:     "", // No group
			expectedUser:  "elastic-agent",
			expectedGroup: "", // Should not be present
		},
		{
			name: "Clear user",
			initialContent: `[Unit]
Description=Elastic Agent
ConditionFileIsExecutable=/opt/Elastic/Agent/elastic-agent

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/opt/Elastic/Agent/elastic-agent
User=olduser
Group=oldgroup
Restart=always
RestartSec=120

[Install]
WantedBy=multi-user.target
`,
			username:      "", // No user
			groupName:     "", // No group
			expectedUser:  "", // Should not be present
			expectedGroup: "", // Should not be present
		},
		{
			name: "Remove existing group when no group specified",
			initialContent: `[Unit]
Description=Elastic Agent
ConditionFileIsExecutable=/opt/Elastic/Agent/elastic-agent

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/opt/Elastic/Agent/elastic-agent
User=olduser
Group=oldgroup
Restart=always
RestartSec=120

[Install]
WantedBy=multi-user.target
`,
			username:      "newuser",
			groupName:     "", // Remove group
			expectedUser:  "newuser",
			expectedGroup: "", // Should be removed
		},
		{
			name: "Add user and group with complex service file",
			initialContent: `[Unit]
Description=Elastic Agent is a unified agent to observe, monitor and protect your system.
ConditionFileIsExecutable=/opt/Elastic/Agent/elastic-agent
After=network.target

[Service]
StartLimitInterval=5
StartLimitBurst=10
ExecStart=/opt/Elastic/Agent/elastic-agent
WorkingDirectory=/opt/Elastic/Agent
Restart=always
RestartSec=120
KillMode=process
LimitNOFILE=65536
StandardOutput=file:/var/log/elastic-agent.out
StandardError=file:/var/log/elastic-agent.err
EnvironmentFile=-/etc/sysconfig/elastic-agent

[Install]
WantedBy=multi-user.target
`,
			username:      "elastic-agent",
			groupName:     "elastic-agent",
			expectedUser:  "elastic-agent",
			expectedGroup: "elastic-agent",
		},
		{
			name: "User at beginning of Service section",
			initialContent: `[Unit]
Description=Elastic Agent

[Service]
User=olduser
ExecStart=/opt/Elastic/Agent/elastic-agent
Restart=always

[Install]
WantedBy=multi-user.target
`,
			username:      "newuser",
			groupName:     "newgroup",
			expectedUser:  "newuser",
			expectedGroup: "newgroup",
		},
		{
			name: "User at end of Service section",
			initialContent: `[Unit]
Description=Elastic Agent

[Service]
ExecStart=/opt/Elastic/Agent/elastic-agent
Restart=always
User=olduser

[Install]
WantedBy=multi-user.target
`,
			username:      "newuser",
			groupName:     "newgroup",
			expectedUser:  "newuser",
			expectedGroup: "newgroup",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a temporary directory and file
			tempDir := t.TempDir()
			serviceFilePath := filepath.Join(tempDir, "test-service.service")

			// Write initial content to the service file
			err := os.WriteFile(serviceFilePath, []byte(tc.initialContent), 0644)
			require.NoError(t, err, "Failed to write initial service file")

			// Call the function under test
			serviceName := "test-service"
			err = changeSystemdServiceFile(serviceName, serviceFilePath, tc.username, tc.groupName)
			require.NoError(t, err, "changeSystemdServiceFile should not return an error")

			// Read the modified content
			modifiedContent, err := os.ReadFile(serviceFilePath)
			require.NoError(t, err, "Failed to read modified service file")

			modifiedStr := string(modifiedContent)

			// Verify User is set correctly
			if tc.expectedUser != "" {
				require.Contains(t, modifiedStr, fmt.Sprintf("User=%s", tc.expectedUser), "User should be set correctly")

				// Count occurrences to ensure only one User entry
				userCount := strings.Count(modifiedStr, "User=")
				require.Equal(t, 1, userCount, "Should have exactly one User entry")

				// Verify User is in [Service] section
				serviceSection := extractServiceSection(modifiedStr)
				require.Contains(t, serviceSection, fmt.Sprintf("User=%s", tc.expectedUser), "User should be in [Service] section")
			} else {
				require.NotContains(t, modifiedStr, "User=", "User should not be present when no user is specified")
			}

			// Verify Group is set correctly
			if tc.expectedGroup != "" {
				require.Contains(t, modifiedStr, fmt.Sprintf("Group=%s", tc.expectedGroup), "Group should be set correctly")

				// Count occurrences to ensure only one Group entry
				groupCount := strings.Count(modifiedStr, "Group=")
				require.Equal(t, 1, groupCount, "Should have exactly one Group entry")

				// Verify Group is in [Service] section
				serviceSection := extractServiceSection(modifiedStr)
				require.Contains(t, serviceSection, fmt.Sprintf("Group=%s", tc.expectedGroup), "Group should be in [Service] section")
			} else {
				require.NotContains(t, modifiedStr, "Group=", "Group should not be present when no group specified")
			}

			// Verify the service file structure is maintained
			require.Contains(t, modifiedStr, "[Unit]", "Unit section should be present")
			require.Contains(t, modifiedStr, "[Service]", "Service section should be present")
			require.Contains(t, modifiedStr, "[Install]", "Install section should be present")

			// Verify other service properties are preserved
			require.Contains(t, modifiedStr, "ExecStart=", "ExecStart should be preserved")
			if strings.Contains(tc.initialContent, "Restart=") {
				require.Contains(t, modifiedStr, "Restart=", "Restart should be preserved")
			}

			// Clean up
			err = os.Remove(serviceFilePath)
			require.NoError(t, err, "Failed to clean up service file")
		})
	}
}

// Helper function to extract the [Service] section from systemd unit content
func extractServiceSection(content string) string {
	lines := strings.Split(content, "\n")
	var serviceLines []string
	inServiceSection := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		if trimmedLine == "[Service]" {
			inServiceSection = true
			serviceLines = append(serviceLines, line)
			continue
		} else if strings.HasPrefix(trimmedLine, "[") && trimmedLine != "[Service]" {
			inServiceSection = false
			continue
		}

		if inServiceSection {
			serviceLines = append(serviceLines, line)
		}
	}

	return strings.Join(serviceLines, "\n")
}
