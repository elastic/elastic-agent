// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/component/hooks"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Hook execution points
const (
	HookPreRun = "pre-run"
)

// Hook types
const (
	HookTypeFixPermissions = "fix-permissions"
)

var supportedHooks = []string{
	HookTypeFixPermissions,
}

// HookDefinition defines a single hook with its type and arguments
type HookDefinition struct {
	Type string                 `config:"hook_type" yaml:"type" json:"type"`
	Args map[string]interface{} `config:"args,omitempty" yaml:"args,omitempty" json:"args,omitempty"`
}

// ComponentHooks defines all hooks for a component organized by execution point
type ComponentHooks struct {
	PreRun  []HookDefinition `config:"pre_run,omitempty" yaml:"pre_run,omitempty" json:"pre_run,omitempty"`
	PostRun []HookDefinition `config:"post_run,omitempty" yaml:"post_run,omitempty" json:"post_run,omitempty"`
}

// GetHooks returns hooks for a specific execution point
func (c *ComponentHooks) GetHooks(point string) []HookDefinition {
	switch point {
	case HookPreRun:
		return c.PreRun
	default:
		return nil
	}
}

// Validate checks that all hooks in ComponentHooks are of known types
func (c *ComponentHooks) Validate() error {
	allHooks := []struct {
		point string
		hooks []HookDefinition
	}{
		{HookPreRun, c.PreRun},
	}

	var validationErrors []string

	for _, hookGroup := range allHooks {
		for i, hook := range hookGroup.hooks {
			if hook.Type == "" {
				validationErrors = append(validationErrors,
					fmt.Sprintf("hook at index %d in %s has empty type", i, hookGroup.point))
				continue
			}

			if !isValidHookType(hook.Type) {
				validationErrors = append(validationErrors,
					fmt.Sprintf("unknown hook type '%s' at index %d in %s. Supported types: %v",
						hook.Type, i, hookGroup.point, supportedHooks))
			}
		}
	}

	if len(validationErrors) > 0 {
		return fmt.Errorf("hook validation failed: %s", strings.Join(validationErrors, "; "))
	}

	return nil
}

// Run executes the hook with its arguments
func (hd *HookDefinition) Run() error {
	switch hd.Type {
	case HookTypeFixPermissions:
		return hd.fixPermissions()
	default:
		return fmt.Errorf("unknown hook type: %s", hd.Type)
	}
}

// GetStringArg safely extracts a string argument
func (hd *HookDefinition) GetArg(key string) (interface{}, bool) {
	if val, exists := hd.Args[key]; exists {
		return val, true
	}
	return "", false
}

// GetStringArg safely extracts a string argument
func (hd *HookDefinition) GetStringArg(key string) (string, bool) {
	if val, exists := hd.Args[key]; exists {
		if str, ok := val.(string); ok {
			return str, true
		}
	}
	return "", false
}

// GetIntArg safely extracts a int argument
func (hd *HookDefinition) GetIntArg(key string) (int, bool) {
	if val, exists := hd.Args[key]; exists {
		switch v := val.(type) {
		case int:
			return v, true
		case int32:
			return int(v), true
		case int64:
			return int(v), true
		case uint64:
			return int(v), true //nolint:gosec // G115 Conversion from int to uint32 is safe here.
		case uint32:
			return int(v), true
		case uint:
			return int(v), true //nolint:gosec // G115 Conversion from int to uint32 is safe here.
		case float32:
			// Handle case where YAML/JSON might parse as float.
			// Make sure we return the value only if it's truly int
			if v == float32(int(v)) {
				return int(v), true
			}
		case float64:
			// Handle case where YAML/JSON might parse as float
			// Make sure we return the value only if it's truly int
			if v == float64(int(v)) {
				return int(v), true
			}
		}
	}
	return 0, false
}

// GetBoolArg safely extracts a boolean argument
func (hd *HookDefinition) GetBoolArg(key string) (bool, bool) {
	if val, exists := hd.Args[key]; exists {
		if b, ok := val.(bool); ok {
			return b, true
		}

	}
	return false, false
}

// GetStringSliceArg safely extracts a string slice argument
func (hd *HookDefinition) GetStringSliceArg(key string) ([]string, bool) {
	if val, exists := hd.Args[key]; exists {
		if slice, ok := val.([]interface{}); ok {
			result := make([]string, len(slice))
			for i, item := range slice {
				if str, ok := item.(string); ok {
					result[i] = str
				} else {
					return nil, false
				}
			}
			return result, true
		}
	}
	return nil, false
}

// ExecuteHooks runs all hooks for a given execution point
func (c *ComponentHooks) ExecuteHooks(point string, log *logger.Logger) error {
	hooks := c.GetHooks(point)
	if len(hooks) == 0 {
		log.Debug("no hook defined")
	}
	for _, hook := range hooks {
		log.Debug("running %q", hook.Type)
		if err := hook.Run(); err != nil {
			return fmt.Errorf("hook %s failed at %s: %w", hook.Type, point, err)
		}
		log.Debug("finished running %q", hook.Type)
	}
	return nil
}

// Hook implementations
func (hd *HookDefinition) fixPermissions() error {
	// example yaml:
	//     hooks:
	//       pre_run:
	//         - hook_type: "fix-permissions"
	//           args:
	//             path: "/opt/elastic/metricbeat" // relative paths will be prefixed with components path
	//			   target_os: [windows]
	//             user: root
	//             group: root
	//             fail_on_path_not_exist: false
	//             mask: 0770 # default 0770 if not specified
	//             # windows specific
	//             inherit_permissions: false

	targetOs, _ := hd.GetStringSliceArg("target_os")
	shouldRun := len(targetOs) == 0 // no target specified means all
	for _, os := range targetOs {
		if os != "" && runtime.GOOS == os {
			shouldRun = true
			break
		}
	}

	if !shouldRun {
		// no need to fail
		return nil
	}

	path, ok := hd.GetStringArg("path")
	if !ok {
		return fmt.Errorf("required parameter 'path' not found in 'fix_permissions' hook")
	}
	path = injectComponentsPath(path)
	inheritPermissions, _ := hd.GetBoolArg("inherit_permissions")
	username, _ := hd.GetStringArg("user")
	groupname, _ := hd.GetStringArg("group")
	failOnNotExist, _ := hd.GetBoolArg("fail_on_path_not_exist")
	mask, _ := hd.GetIntArg("mask")

	return hooks.FixPermissions(path, inheritPermissions, username, groupname, failOnNotExist, mask)
}

// isValidHookType checks if the hook type is supported
func isValidHookType(hookType string) bool {
	for _, supported := range supportedHooks {
		if supported == hookType {
			return true
		}
	}

	return false
}

func injectComponentsPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}

	return filepath.Clean(
		filepath.Join(
			paths.VersionedHome(paths.Top()),
			"components",
			path,
		),
	)
}
