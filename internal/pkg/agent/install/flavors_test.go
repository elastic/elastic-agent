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

func TestAllowedSubpathsForFlavor(t *testing.T) {
	binarySuffix := ""
	if runtime.GOOS == "windows" {
		binarySuffix = ".exe"
	}
	versionedHome := t.TempDir()
    tests := []struct {
        name           string
        flavor         string
        specFiles      map[string]string
        wantError      bool
        errorContains  string
        wantSubpaths   []string
    }{
        {
            name:   "basic flavor with specs",
            flavor: FlavorBasic,
            specFiles: map[string]string{
                "agentbeat": "component_files:\n- modules/*\n",
                "osqueryd": "component_files:\n- data/*\n",
            },
            wantSubpaths: []string{
                "agentbeat"+binarySuffix,
                "agentbeat.yml",
                "agentbeat.spec.yml",
                "modules/*",
                "osqueryd"+binarySuffix,
                "osqueryd.yml", 
                "osqueryd.spec.yml",
                "data/*",
            },
        },
        {
            name:      "unknown flavor returns error",
            flavor:    "unknown",
            wantError: true,
            errorContains: ErrUnknownFlavor.Error(),
        },
        {
            name:    "empty version home returns default paths",
            flavor:  FlavorBasic,
            wantSubpaths: []string{},
        },
        {
            name:   "servers flavor with specs",
            flavor: FlavorServers,
            specFiles: map[string]string{
                "agentbeat": "component_files:\n- modules/*\n",
                "apm-server": "component_files:\n- apm.bundle.zip\n",
                "cloudbeat": "component_files:\n- rules/*\n",
            },
            wantSubpaths: []string{
                "agentbeat"+binarySuffix,
                "agentbeat.yml",
                "agentbeat.spec.yml",
                "modules/*",
                "apm-server"+binarySuffix,
                "apm-server.yml",
                "apm-server.spec.yml", 
                "apm.bundle.zip",
                "cloudbeat"+binarySuffix,
                "cloudbeat.yml",
                "cloudbeat.spec.yml",
                "rules/*",
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Create temp dir with spec files
            componentsDir := filepath.Join(versionedHome, "components")
            require.NoError(t, os.MkdirAll(componentsDir, 0755))

            // Write spec files
            for component, content := range tt.specFiles {
                specPath := filepath.Join(componentsDir, component+".spec.yml")
                require.NoError(t, os.WriteFile(specPath, []byte(content), 0644))
				defer os.Remove(specPath)
            }

            // Test function
            subpaths, err := allowedSubpathsForFlavor(versionedHome, tt.flavor)

            if tt.wantError {
                require.Error(t, err)
                assert.Contains(t, err.Error(), tt.errorContains)
                return
            }

            require.NoError(t, err)
            sort.Strings(tt.wantSubpaths)
            sort.Strings(subpaths) 
            assert.Equal(t, tt.wantSubpaths, subpaths)
        })
    }
}

func TestSkipComponentsPathWithSubpathsFn(t *testing.T) {
    tests := []struct {
        name         string
        allowedPaths []string
        testPaths    map[string]bool // path -> should skip
    }{
        // Case 1: Empty allowed paths
        {
            name: "empty allowed paths skips nothing",
            allowedPaths: nil,
            testPaths: map[string]bool{
                filepath.Join("data", "components", "test.txt"): false,
                filepath.Join("data", "components", "dir", "file"): false,
            },
        },

        // Case 2: Exact file matches
        {
            name: "exact matches",
            allowedPaths: []string{
                "agentbeat.exe",
                "agentbeat.yml",
            },
            testPaths: map[string]bool{
                filepath.Join("data", "components", "agentbeat.exe"): false, // allowed
                filepath.Join("data", "components", "other.exe"): true,     // skipped
            },
        },

        // Case 3: Directory wildcards
        {
            name: "directory wildcards", 
            allowedPaths: []string{
                "modules/*",
            },
            testPaths: map[string]bool{
                filepath.Join("data", "components", "modules", "mod1"): false, // allowed
                filepath.Join("data", "components", "other", "logs"): true,   // skipped
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            skipFn, err := SkipComponentsPathWithSubpathsFn(tt.allowedPaths)
            require.NoError(t, err)

            for path, wantSkip := range tt.testPaths {
                got := skipFn(path)
                assert.Equal(t, wantSkip, got,
                    "Path %s: wanted skip=%v, got skip=%v", path, wantSkip, got)
            }
        })
    }
}

func TestSkipComponentsPathFn(t *testing.T) {
    tests := []struct {
        name           string
        flavor         string
        specFiles      map[string]string // component -> spec content
        testPaths      map[string]bool   // path -> should skip
        wantError      bool
        errorContains  string
    }{
        {
            name:   "basic flavor components",
            flavor: FlavorBasic,
            specFiles: map[string]string{
                "agentbeat": "component_files:\n- data/*\n",
                "osqueryd": "component_files:\n- logs/*\n",
            },
            testPaths: map[string]bool{
                filepath.Join("data", "components",  "data", "file.txt"): false,
                filepath.Join("data", "components",  "logs", "error.log"): false,
                filepath.Join("data", "components", "rules", "rule1.yml"): true,
            },
        },
        {
            name:   "servers flavor components",
            flavor: FlavorServers,
            specFiles: map[string]string{
                "cloudbeat": "component_files:\n- rules/*\n",
                "apm-server": "component_files:\n- apm.bundle.zip\n",
            },
            testPaths: map[string]bool{
                filepath.Join("data", "components", "rules", "rule1.yml"): false,
                filepath.Join("data", "components",  "apm.bundle.zip"): false,
                filepath.Join("data", "components",  "file.txt"): true,
            },
        },
        {
            name:    "invalid flavor",
            flavor:  "invalid",
            wantError: true,
            errorContains: ErrUnknownFlavor.Error(),
        },
        {
            name:    "no spec file",
            flavor:  FlavorBasic,
            testPaths: map[string]bool{
                filepath.Join("data", "components", "agentbeat.exe"): true,
                filepath.Join("data", "components", "osqueryd.exe"): true,
            },
        },
        {
            name:    "no flavor",
            flavor:  "",
            specFiles: map[string]string{
                "agentbeat": "component_files:\n- data/*\n",
                "osqueryd": "component_files:\n- logs/*\n",
            },
            testPaths: map[string]bool{
                filepath.Join("data", "components",  "data", "file.txt"): false,
                filepath.Join("data", "components",  "logs", "error.log"): false,
                filepath.Join("data", "components", "rules", "rule1.yml"): true,
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup temp dir
            tmpDir := t.TempDir()
            if len(tt.specFiles) > 0 {
                componentsDir := filepath.Join(tmpDir, "components")
                require.NoError(t, os.MkdirAll(componentsDir, 0755))

                // Create spec files
                for component, content := range tt.specFiles {
                    specPath := filepath.Join(componentsDir, component+".spec.yml")
                    require.NoError(t, os.WriteFile(specPath, []byte(content), 0644))
                }
            }

            // Test function
            skipFn, err := SkipComponentsPathFn(tmpDir, tt.flavor)

            if tt.wantError {
                require.Error(t, err)
                assert.Contains(t, err.Error(), tt.errorContains)
                return
            }

            require.NoError(t, err)
            require.NotNil(t, skipFn)

            // Test paths
            for path, wantSkip := range tt.testPaths {
                got := skipFn(path)
                assert.Equal(t, wantSkip, got,
                    "Path %s: wanted skip=%v, got skip=%v", path, wantSkip, got)
            }
        })
    }
}