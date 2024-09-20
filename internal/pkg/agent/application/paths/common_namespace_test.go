// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package paths

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInstallNamespace(t *testing.T) {
	namespace := "testing"
	basePath := filepath.Join("base", "path")

	// Add whitespace to ensure it gets removed.
	SetInstallNamespace(" " + namespace + "\t   ")

	assert.Equal(t, namespace, InstallNamespace())
	assert.True(t, InInstallNamespace())
	assert.Equal(t, filepath.Join(basePath, "Elastic", fmt.Sprintf(installDirNamespaceFmt, namespace)), InstallPath(basePath))
	assert.Equal(t, fmt.Sprintf(serviceNameNamespaceFmt, namespace), ServiceName())
	assert.Equal(t, fmt.Sprintf(serviceDisplayNameNamespaceFmt, namespace), ServiceDisplayName())
	assert.Equal(t, ShellWrapperPathForNamespace(namespace), ShellWrapperPath())
	assert.Equal(t, controlSocketRunSymlinkForNamespace(namespace), ControlSocketRunSymlink(namespace))
}

func TestInstallNoNamespace(t *testing.T) {
	namespace := ""
	basePath := filepath.Join("base", "path")
	SetInstallNamespace(namespace)

	assert.Equal(t, namespace, InstallNamespace())
	assert.False(t, InInstallNamespace())
	assert.Equal(t, filepath.Join(basePath, "Elastic", installDir), InstallPath(basePath))
	assert.Equal(t, serviceName, ServiceName())
	assert.Equal(t, serviceDisplayName, ServiceDisplayName())
	assert.Equal(t, shellWrapperPath, ShellWrapperPath())
	assert.Equal(t, controlSocketRunSymlink, ControlSocketRunSymlink(namespace))
}

func TestParseNamespaceFromDirName(t *testing.T) {
	testcases := []struct {
		name      string
		dir       string
		namespace string
	}{
		{name: "empty", dir: "", namespace: ""},
		{name: "none", dir: "Agent", namespace: ""},
		{name: "develop", dir: "Agent-Development", namespace: "Development"},
		{name: "dashes", dir: "Agent-With-Dashes", namespace: "With-Dashes"},
		{name: "special", dir: "Agent-@!$%^&*()-_+=", namespace: "@!$%^&*()-_+="},
		{name: "format", dir: "Agent-%s%d%v%t", namespace: "%s%d%v%t"},
		{name: "spaces", dir: "Agent- Development \t", namespace: " Development \t"},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equalf(t, tc.namespace, parseNamespaceFromDir(tc.dir), "parsing %s", tc.dir)

			// Special case: if the directory is empty the install dir is the default "Agent" not "Agent-"
			wantDir := tc.dir
			if wantDir == "" {
				wantDir = installDir
			}
			assert.Equal(t, wantDir, InstallDirNameForNamespace(tc.namespace))
		})
	}
}

func TestParseNamespaceFromDirNameWithoutAgentPrefix(t *testing.T) {
	assert.Equal(t, "", parseNamespaceFromDir("Beats-Development"))
}
