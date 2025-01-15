// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComponentsForFlavor(t *testing.T) {
    tests := []struct {
        name          string
        flavor        string
        allowFallback bool
        wantError     bool
        errorContains string
        wantComponents []string
    }{
        {
            name:          "empty flavor with fallback returns default",
            flavor:        "",
            allowFallback: true,
            wantComponents: flavorsRegistry[DefaultFlavor],
        },
        {
            name:          "empty flavor without fallback returns error",
            flavor:        "",
            allowFallback: false,
            wantError:    true,
            errorContains: ErrUnknownFlavor.Error(),
        },
        {
            name:          "unknown flavor with fallback returns error",
            flavor:        "unknown",
            allowFallback: true,
            wantError:    true,
            errorContains: ErrUnknownFlavor.Error(),
        },
        {
            name:          "unknown flavor without fallback returns error",
            flavor:        "unknown", 
            allowFallback: false,
            wantError:    true,
            errorContains: ErrUnknownFlavor.Error(),
        },
        {
            name:          "basic flavor returns components",
            flavor:        FlavorBasic,
            allowFallback: false,
            wantComponents: flavorsRegistry[FlavorBasic],
        },
        {
            name:          "servers flavor returns components",
            flavor:        FlavorServers,
            allowFallback: false,
            wantComponents: flavorsRegistry[FlavorServers],
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            components, err := componentsForFlavor(tt.flavor, tt.allowFallback)
            
            if tt.wantError { 
                require.Error(t, err)
                assert.Contains(t, err.Error(), tt.errorContains)
                return
            }

            require.NoError(t, err)
            assert.Equal(t, tt.wantComponents, components)
        })
    }
}

func TestSubpathsForComponent(t *testing.T) {
	binarySuffix := ""
	if runtime.GOOS == "windows" {	
		binarySuffix = ".exe"
	}
    tests := []struct {
        name           string
        component      string
        wantError      bool
        errorContains  string
        wantSubpaths   []string
		specFileContent string
    }{
        {
            name:      "empty component returns error",
            component: "",
            wantError: true,
            errorContains: "empty component name",
        },
        {
            name:      "basic component returns paths",
            component: "agentbeat",
            wantSubpaths: []string{
                "agentbeat"+binarySuffix,
                "agentbeat.yml",
                "agentbeat.spec.yml",
            },
			specFileContent: "version: 2",
        },
        {
            name:      "server component without spec file returns nothing",
            component: "apm-server",
            wantSubpaths: nil,
        },
        {
            name:      "server component with spec paths returns paths",
            component: "apm-server",
            wantSubpaths: []string{
                "apm-server"+binarySuffix,
                "apm-server.yml",
                "apm-server.spec.yml",
				"modules/*",
				"apm.bundle.zip",
            },
			specFileContent: `component_files:
- modules/*
- apm.bundle.zip`,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
			//write spec file content to temp file
				tmpDir := t.TempDir()
			if tt.specFileContent != "" {
				specFilePath := filepath.Join(tmpDir, tt.component+".spec.yml")
				err := os.WriteFile(specFilePath, []byte(tt.specFileContent), 0644)
				require.NoError(t, err)
				defer os.Remove(specFilePath)
			}

            subpaths, err := subpathsForComponent(tt.component, tmpDir)
            
            if tt.wantError {
                require.Error(t, err)
                assert.Contains(t, err.Error(), tt.errorContains)
                return
            }

            require.NoError(t, err)
			sort.Strings(tt.wantSubpaths)
			sort.Strings(subpaths)
            assert.EqualValues(t, tt.wantSubpaths, subpaths)
        })
    }
}
