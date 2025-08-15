// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

func TestHookDefinition_GetArg(t *testing.T) {
	testCases := []struct {
		name     string
		args     map[string]interface{}
		key      string
		expected interface{}
		exists   bool
	}{
		{
			name:     "existing string arg",
			args:     map[string]interface{}{"test": "value"},
			key:      "test",
			expected: "value",
			exists:   true,
		},
		{
			name:     "existing int arg",
			args:     map[string]interface{}{"count": 42},
			key:      "count",
			expected: 42,
			exists:   true,
		},
		{
			name:     "non-existing arg",
			args:     map[string]interface{}{"test": "value"},
			key:      "missing",
			expected: "",
			exists:   false,
		},
		{
			name:     "nil args",
			args:     nil,
			key:      "test",
			expected: "",
			exists:   false,
		},
		{
			name:     "empty args",
			args:     map[string]interface{}{},
			key:      "test",
			expected: "",
			exists:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hd := &HookDefinition{Args: tc.args}
			value, exists := hd.GetArg(tc.key)
			assert.Equal(t, tc.exists, exists)
			if tc.exists {
				assert.Equal(t, tc.expected, value)
			}
		})
	}
}

func TestHookDefinition_GetStringArg(t *testing.T) {
	testCases := []struct {
		name     string
		args     map[string]interface{}
		key      string
		expected string
		exists   bool
	}{
		{
			name:     "valid string",
			args:     map[string]interface{}{"path": "/opt/elastic"},
			key:      "path",
			expected: "/opt/elastic",
			exists:   true,
		},
		{
			name:     "empty string",
			args:     map[string]interface{}{"path": ""},
			key:      "path",
			expected: "",
			exists:   true,
		},
		{
			name:     "non-string value",
			args:     map[string]interface{}{"path": 123},
			key:      "path",
			expected: "",
			exists:   false,
		},
		{
			name:     "non-existing key",
			args:     map[string]interface{}{"other": "value"},
			key:      "path",
			expected: "",
			exists:   false,
		},
		{
			name:     "nil value",
			args:     map[string]interface{}{"path": nil},
			key:      "path",
			expected: "",
			exists:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hd := &HookDefinition{Args: tc.args}
			value, exists := hd.GetStringArg(tc.key)
			assert.Equal(t, tc.expected, value)
			assert.Equal(t, tc.exists, exists)
		})
	}
}

func TestHookDefinition_GetIntArg(t *testing.T) {
	testCases := []struct {
		name     string
		args     map[string]interface{}
		key      string
		expected int
		exists   bool
	}{
		{
			name:     "valid int",
			args:     map[string]interface{}{"mask": 755},
			key:      "mask",
			expected: 755,
			exists:   true,
		},
		{
			name:     "int32",
			args:     map[string]interface{}{"mask": int32(644)},
			key:      "mask",
			expected: 644,
			exists:   true,
		},
		{
			name:     "int64",
			args:     map[string]interface{}{"mask": int64(777)},
			key:      "mask",
			expected: 777,
			exists:   true,
		},
		{
			name:     "uint",
			args:     map[string]interface{}{"mask": uint(600)},
			key:      "mask",
			expected: 600,
			exists:   true,
		},
		{
			name:     "uint32",
			args:     map[string]interface{}{"mask": uint32(666)},
			key:      "mask",
			expected: 666,
			exists:   true,
		},
		{
			name:     "uint64",
			args:     map[string]interface{}{"mask": uint64(700)},
			key:      "mask",
			expected: 700,
			exists:   true,
		},
		{
			name:     "float32 whole number",
			args:     map[string]interface{}{"mask": float32(755.0)},
			key:      "mask",
			expected: 755,
			exists:   true,
		},
		{
			name:     "float64 whole number",
			args:     map[string]interface{}{"mask": float64(644.0)},
			key:      "mask",
			expected: 644,
			exists:   true,
		},
		{
			name:     "float32 with decimal",
			args:     map[string]interface{}{"mask": float32(755.5)},
			key:      "mask",
			expected: 0,
			exists:   false,
		},
		{
			name:     "float64 with decimal",
			args:     map[string]interface{}{"mask": float64(644.7)},
			key:      "mask",
			expected: 0,
			exists:   false,
		},
		{
			name:     "string value",
			args:     map[string]interface{}{"mask": "755"},
			key:      "mask",
			expected: 0,
			exists:   false,
		},
		{
			name:     "non-existing key",
			args:     map[string]interface{}{"other": 123},
			key:      "mask",
			expected: 0,
			exists:   false,
		},
		{
			name:     "nil value",
			args:     map[string]interface{}{"mask": nil},
			key:      "mask",
			expected: 0,
			exists:   false,
		},
		{
			name:     "filemode value",
			args:     map[string]interface{}{"mask": 0640},
			key:      "mask",
			expected: 0640,
			exists:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hd := &HookDefinition{Args: tc.args}
			value, exists := hd.GetIntArg(tc.key)
			assert.Equal(t, tc.expected, value)
			assert.Equal(t, tc.exists, exists)
		})
	}
}

func TestHookDefinition_GetBoolArg(t *testing.T) {
	testCases := []struct {
		name     string
		args     map[string]interface{}
		key      string
		expected bool
		exists   bool
	}{
		{
			name:     "true value",
			args:     map[string]interface{}{"inherit": true},
			key:      "inherit",
			expected: true,
			exists:   true,
		},
		{
			name:     "false value",
			args:     map[string]interface{}{"inherit": false},
			key:      "inherit",
			expected: false,
			exists:   true,
		},
		{
			name:     "string value",
			args:     map[string]interface{}{"inherit": "true"},
			key:      "inherit",
			expected: false,
			exists:   false,
		},
		{
			name:     "int value",
			args:     map[string]interface{}{"inherit": 1},
			key:      "inherit",
			expected: false,
			exists:   false,
		},
		{
			name:     "non-existing key",
			args:     map[string]interface{}{"other": true},
			key:      "inherit",
			expected: false,
			exists:   false,
		},
		{
			name:     "nil value",
			args:     map[string]interface{}{"inherit": nil},
			key:      "inherit",
			expected: false,
			exists:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hd := &HookDefinition{Args: tc.args}
			value, exists := hd.GetBoolArg(tc.key)
			assert.Equal(t, tc.expected, value)
			assert.Equal(t, tc.exists, exists)
		})
	}
}

func TestHookDefinition_GetStringSliceArg(t *testing.T) {
	testCases := []struct {
		name     string
		args     map[string]interface{}
		key      string
		expected []string
		exists   bool
	}{
		{
			name: "valid string slice",
			args: map[string]interface{}{
				"users": []interface{}{"root", "elastic", "agent"},
			},
			key:      "users",
			expected: []string{"root", "elastic", "agent"},
			exists:   true,
		},
		{
			name: "empty string slice",
			args: map[string]interface{}{
				"users": []interface{}{},
			},
			key:      "users",
			expected: []string{},
			exists:   true,
		},
		{
			name: "single item slice",
			args: map[string]interface{}{
				"users": []interface{}{"admin"},
			},
			key:      "users",
			expected: []string{"admin"},
			exists:   true,
		},
		{
			name: "mixed types in slice",
			args: map[string]interface{}{
				"users": []interface{}{"root", 123, "elastic"},
			},
			key:      "users",
			expected: nil,
			exists:   false,
		},
		{
			name: "non-slice value",
			args: map[string]interface{}{
				"users": "single-user",
			},
			key:      "users",
			expected: nil,
			exists:   false,
		},
		{
			name: "slice with nil elements",
			args: map[string]interface{}{
				"users": []interface{}{"root", nil, "elastic"},
			},
			key:      "users",
			expected: nil,
			exists:   false,
		},
		{
			name:     "non-existing key",
			args:     map[string]interface{}{"other": []interface{}{"value"}},
			key:      "users",
			expected: nil,
			exists:   false,
		},
		{
			name: "nil value",
			args: map[string]interface{}{
				"users": nil,
			},
			key:      "users",
			expected: nil,
			exists:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hd := &HookDefinition{Args: tc.args}
			value, exists := hd.GetStringSliceArg(tc.key)
			assert.Equal(t, tc.expected, value)
			assert.Equal(t, tc.exists, exists)
		})
	}
}

func TestHookDefinition_GetArgMethods_Integration(t *testing.T) {
	// Test with realistic hook arguments
	hd := &HookDefinition{
		Type: "apply-permissions",
		Args: map[string]interface{}{
			"path":                   "/opt/elastic/agent",
			"mask":                   755,
			"inherit_permissions":    true,
			"fail_on_path_not_exist": false,
			"target_os":              []interface{}{"linux", "darwin"},
			"timeout":                float64(30.0), // Common YAML parsing result
			"retries":                int32(3),
			"debug":                  false,
		},
	}

	// Test all methods work together
	path, ok := hd.GetStringArg("path")
	assert.True(t, ok)
	assert.Equal(t, "/opt/elastic/agent", path)

	mask, ok := hd.GetIntArg("mask")
	assert.True(t, ok)
	assert.Equal(t, 755, mask)

	inherit, ok := hd.GetBoolArg("inherit_permissions")
	assert.True(t, ok)
	assert.True(t, inherit)

	failOnNotExist, ok := hd.GetBoolArg("fail_on_path_not_exist")
	assert.True(t, ok)
	assert.False(t, failOnNotExist)

	targetOS, ok := hd.GetStringSliceArg("target_os")
	assert.True(t, ok)
	assert.Equal(t, []string{"linux", "darwin"}, targetOS)

	timeout, ok := hd.GetIntArg("timeout")
	assert.True(t, ok)
	assert.Equal(t, 30, timeout)

	retries, ok := hd.GetIntArg("retries")
	assert.True(t, ok)
	assert.Equal(t, 3, retries)

	debug, ok := hd.GetBoolArg("debug")
	assert.True(t, ok)
	assert.False(t, debug)

	// Test non-existing args
	_, ok = hd.GetStringArg("non_existing")
	assert.False(t, ok)

	_, ok = hd.GetIntArg("non_existing")
	assert.False(t, ok)

	_, ok = hd.GetBoolArg("non_existing")
	assert.False(t, ok)

	_, ok = hd.GetStringSliceArg("non_existing")
	assert.False(t, ok)
}

func TestComponentHooks_GetHooks(t *testing.T) {
	// Setup test hooks
	preRunHooks := []HookDefinition{
		{
			Type: "apply-permissions",
			Args: map[string]interface{}{
				"path": "/opt/elastic/pre",
				"mask": 755,
			},
		},
		{
			Type: "cleanup",
			Args: map[string]interface{}{
				"paths": []interface{}{"/tmp/pre1", "/tmp/pre2"},
			},
		},
	}

	componentHooks := &ComponentHooks{
		PreRun: preRunHooks,
	}

	testCases := []struct {
		name     string
		point    string
		expected []HookDefinition
	}{
		{
			name:     "get pre-run hooks",
			point:    HookPreRun,
			expected: preRunHooks,
		},
		{
			name:     "get hooks for unknown point",
			point:    "unknown-point",
			expected: nil,
		},
		{
			name:     "get hooks for empty point",
			point:    "",
			expected: nil,
		},
		{
			name:     "get hooks with case sensitive point",
			point:    "PRE-RUN", // Different case
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := componentHooks.GetHooks(tc.point)
			assert.Equal(t, tc.expected, result)

			// Additional validation: ensure we get a slice even if nil
			if tc.expected == nil {
				assert.Len(t, result, 0, "Should return empty slice for unknown points but got %v", result)
			} else {
				assert.NotNil(t, result, "Result should not be nil for slice comparison")
				assert.Len(t, result, len(tc.expected), "Should return correct number of hooks")

				// Verify each hook individually
				for i, expectedHook := range tc.expected {
					assert.Equal(t, expectedHook.Type, result[i].Type, "Hook type should match")
					assert.Equal(t, expectedHook.Args, result[i].Args, "Hook args should match")
				}
			}
		})
	}
}

func TestComponentHooks_GetHooks_Integration(t *testing.T) {
	// Test with realistic hook configuration
	componentHooks := &ComponentHooks{
		PreRun: []HookDefinition{
			{
				Type: "apply-permissions",
				Args: map[string]interface{}{
					"path":                "/opt/elastic/filebeat",
					"mask":                755,
					"user":                "elastic",
					"group":               "elastic",
					"inherit_permissions": false,
					"target_os":           []interface{}{"linux", "darwin"},
				},
			},
		},
	}

	// Test that we can get and validate the returned hooks
	preRunHooks := componentHooks.GetHooks(HookPreRun)
	assert.Len(t, preRunHooks, 1)

	hook := preRunHooks[0]
	assert.Equal(t, "apply-permissions", hook.Type)

	// Verify we can extract arguments correctly
	path, ok := hook.GetStringArg("path")
	assert.True(t, ok)
	assert.Equal(t, "/opt/elastic/filebeat", path)

	mask, ok := hook.GetIntArg("mask")
	assert.True(t, ok)
	assert.Equal(t, 755, mask)

	targetOS, ok := hook.GetStringSliceArg("target_os")
	assert.True(t, ok)
	assert.Equal(t, []string{"linux", "darwin"}, targetOS)
}

func TestComponentHooks_Validate(t *testing.T) {
	testCases := []struct {
		name        string
		hooks       ComponentHooks
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid hooks",
			hooks: ComponentHooks{
				PreRun: []HookDefinition{
					{
						Type: HookTypeApplyPermissions,
						Args: map[string]interface{}{
							"path": "/opt/elastic",
							"mask": 0755,
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "multiple valid hooks",
			hooks: ComponentHooks{
				PreRun: []HookDefinition{
					{
						Type: HookTypeApplyPermissions,
						Args: map[string]interface{}{
							"path": "/opt/elastic",
						},
					},
					{
						Type: HookTypeApplyPermissions,
						Args: map[string]interface{}{
							"path": "/var/log/elastic",
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "empty hook type",
			hooks: ComponentHooks{
				PreRun: []HookDefinition{
					{
						Type: "",
						Args: map[string]interface{}{
							"path": "/opt/elastic",
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "hook at index 0 in pre-run has empty type",
		},
		{
			name: "invalid hook type",
			hooks: ComponentHooks{
				PreRun: []HookDefinition{
					{
						Type: "unknown-hook-type",
						Args: map[string]interface{}{
							"path": "/opt/elastic",
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "unknown hook type 'unknown-hook-type' at index 0 in pre-run",
		},
		{
			name: "multiple validation errors",
			hooks: ComponentHooks{
				PreRun: []HookDefinition{
					{
						Type: "",
						Args: map[string]interface{}{
							"path": "/opt/elastic",
						},
					},
					{
						Type: "invalid-type",
						Args: map[string]interface{}{
							"path": "/var/log",
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "hook at index 0 in pre-run has empty type; unknown hook type 'invalid-type' at index 1 in pre-run",
		},
		{
			name: "no hooks defined",
			hooks: ComponentHooks{
				PreRun: []HookDefinition{},
			},
			expectError: false,
		},
		{
			name:        "nil hooks",
			hooks:       ComponentHooks{},
			expectError: false,
		},
		{
			name: "hook with no args",
			hooks: ComponentHooks{
				PreRun: []HookDefinition{
					{
						Type: HookTypeApplyPermissions,
					},
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.hooks.Validate()

			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInjectComponentsPath(t *testing.T) {
	componentsPrefix := filepath.Join(paths.VersionedHome(paths.Top()), "components")
	var testCases []struct {
		name     string
		input    string
		expected string
	}

	if runtime.GOOS != "windows" {
		testCases = []struct {
			name     string
			input    string
			expected string
		}{

			{
				name:     "absolute path unchanged",
				input:    "/opt/elastic/agent",
				expected: "/opt/elastic/agent",
			},
			{
				name:     "relative path gets components prefix",
				input:    "filebeat/config",
				expected: filepath.Clean(filepath.Join(componentsPrefix, "filebeat/config")),
			},
			{
				name:     "single file relative path",
				input:    "config.yml",
				expected: filepath.Clean(filepath.Join(componentsPrefix, "config.yml")),
			},
			{
				name:     "nested relative path",
				input:    "beats/filebeat/data",
				expected: filepath.Clean(filepath.Join(componentsPrefix, "beats/filebeat/data")),
			},
			{
				name:     "current directory reference",
				input:    "./config",
				expected: filepath.Clean(filepath.Join(componentsPrefix, "./config")),
			},
			{
				name:     "parent directory reference",
				input:    "../shared/config",
				expected: filepath.Clean(filepath.Join(componentsPrefix, "../shared/config")),
			},
			{
				name:     "empty path",
				input:    "",
				expected: filepath.Clean(filepath.Join(componentsPrefix, "")),
			},
			{
				name:     "path with trailing slash",
				input:    "filebeat/",
				expected: filepath.Clean(filepath.Join(componentsPrefix, "filebeat/")),
			},
			{
				name:     "path with multiple separators",
				input:    "filebeat//config//file.yml",
				expected: filepath.Clean(filepath.Join(componentsPrefix, "filebeat//config//file.yml")),
			},
		}
	}

	// Add platform-specific test cases
	if runtime.GOOS == "windows" {
		testCases = []struct {
			name     string
			input    string
			expected string
		}{
			{
				name:     "windows absolute path unchanged",
				input:    "C:\\Program Files\\Elastic\\Agent",
				expected: "C:\\Program Files\\Elastic\\Agent",
			},
			{
				name:     "windows UNC path unchanged",
				input:    "\\\\server\\share\\path",
				expected: "\\\\server\\share\\path",
			},
			{
				name:     "windows relative path with backslashes",
				input:    "filebeat\\config\\file.yml",
				expected: filepath.Clean(filepath.Join(componentsPrefix, "filebeat\\config\\file.yml")),
			},
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := injectComponentsPath(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
