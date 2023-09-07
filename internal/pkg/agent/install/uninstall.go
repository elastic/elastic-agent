// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kardianos/service"

	"github.com/elastic/elastic-agent-system-metrics/metric/system/process"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	aerrors "github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vars"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/config/operations"
	"github.com/elastic/elastic-agent/pkg/component"
	comprt "github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
)

// Uninstall uninstalls persistently Elastic Agent on the system.
func Uninstall(cfgFile, topPath, uninstallToken string) error {
	// uninstall the current service
	svc, err := newService(topPath)
	if err != nil {
		return err
	}
	status, _ := svc.Status()

	if status == service.StatusRunning {
		err := svc.Stop()
		if err != nil {
			return aerrors.New(
				err,
				fmt.Sprintf("failed to stop service (%s)", paths.ServiceName),
				aerrors.M("service", paths.ServiceName))
		}
	}

	// kill any running watcher
	if err := killWatcher(); err != nil {
		return fmt.Errorf("failed trying to kill any running watcher: %w", err)
	}

	// Uninstall components first
	if err := uninstallComponents(context.Background(), cfgFile, uninstallToken); err != nil {
		// If service status was running it was stopped to uninstall the components.
		// If the components uninstall failed start the service again
		if status == service.StatusRunning {
			if startErr := svc.Start(); startErr != nil {
				return aerrors.New(
					err,
					fmt.Sprintf("failed to restart service (%s), after failed components uninstall: %v", paths.ServiceName, startErr),
					aerrors.M("service", paths.ServiceName))
			}
		}
		return err
	}

	// Uninstall service only after components were uninstalled successfully
	_ = svc.Uninstall()

	// remove, if present on platform
	if paths.ShellWrapperPath != "" {
		err = os.Remove(paths.ShellWrapperPath)
		if !os.IsNotExist(err) && err != nil {
			return aerrors.New(
				err,
				fmt.Sprintf("failed to remove shell wrapper (%s)", paths.ShellWrapperPath),
				aerrors.M("destination", paths.ShellWrapperPath))
		}
	}

	// remove existing directory
	err = RemovePath(topPath)
	if err != nil {
		return aerrors.New(
			err,
			fmt.Sprintf("failed to remove installation directory (%s)", paths.Top()),
			aerrors.M("directory", paths.Top()))
	}

	return nil
}

// RemovePath helps with removal path where there is a probability
// of running into an executable running that might prevent removal
// on Windows.
//
// On Windows it is possible that a removal can spuriously error due
// to an ERROR_SHARING_VIOLATION. RemovePath will retry up to 2
// seconds if it keeps getting that error.
func RemovePath(path string) error {
	const arbitraryTimeout = 5 * time.Second
	start := time.Now()
	nextSleep := 1 * time.Millisecond
	for {
		err := os.RemoveAll(path)
		if err == nil {
			return nil
		}
		if isBlockingOnExe(err) {
			// try to remove the blocking exe
			err = removeBlockingExe(err)
		}
		if err == nil {
			return nil
		}
		if !isRetryableError(err) {
			return err
		}

		if d := time.Since(start) + nextSleep; d >= arbitraryTimeout {
			return err
		}
	}
}

func RemoveBut(path string, bestEffort bool, exceptions ...string) error {
	if len(exceptions) == 0 {
		return RemovePath(path)
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	for _, f := range files {
		if containsString(f.Name(), exceptions, runtime.GOOS != component.Windows) {
			continue
		}

		err = RemovePath(filepath.Join(path, f.Name()))
		if !bestEffort && err != nil {
			return err
		}
	}

	return err
}

func containsString(str string, a []string, caseSensitive bool) bool {
	if !caseSensitive {
		str = strings.ToLower(str)
	}
	for _, v := range a {
		if !caseSensitive {
			v = strings.ToLower(v)
		}
		if str == v {
			return true
		}
	}

	return false
}

func uninstallComponents(ctx context.Context, cfgFile string, uninstallToken string) error {
	log, err := logger.NewWithLogpLevel("", logp.ErrorLevel, false)
	if err != nil {
		return err
	}

	platform, err := component.LoadPlatformDetail()
	if err != nil {
		return fmt.Errorf("failed to gather system information: %w", err)
	}

	specs, err := component.LoadRuntimeSpecs(paths.Components(), platform)
	if err != nil {
		return fmt.Errorf("failed to detect inputs and outputs: %w", err)
	}

	cfg, err := operations.LoadFullAgentConfig(ctx, log, cfgFile, false)
	if err != nil {
		return err
	}

	cfg, err = applyDynamics(ctx, log, cfg)
	if err != nil {
		return err
	}

	comps, err := serviceComponentsFromConfig(specs, cfg)
	if err != nil {
		return err
	}

	// nothing to remove
	if len(comps) == 0 {
		return nil
	}

	// Need to read the features from config on uninstall, in order to set the tamper protection feature flag correctly
	if err := features.Apply(cfg); err != nil {
		return fmt.Errorf("could not parse and apply feature flags config: %w", err)
	}

	// check caps so we don't try uninstalling things that were already
	// prevented from installing
	caps, err := capabilities.LoadFile(paths.AgentCapabilitiesPath(), log)
	if err != nil {
		return err
	}

	// remove each service component
	for _, comp := range comps {
		if !caps.AllowInput(comp.InputType) || !caps.AllowOutput(comp.OutputType) {
			// This component is not active
			continue
		}
		if err := uninstallServiceComponent(ctx, log, comp, uninstallToken); err != nil {
			os.Stderr.WriteString(fmt.Sprintf("failed to uninstall component %q: %s\n", comp.ID, err))
			// The decision was made to change the behaviour and leave the Agent installed if Endpoint uninstall fails
			// https://github.com/elastic/elastic-agent/pull/2708#issuecomment-1574251911
			// Thus returning error here.
			return err
		}
	}

	return nil
}

func uninstallServiceComponent(ctx context.Context, log *logp.Logger, comp component.Component, uninstallToken string) error {
	// Do not use infinite retries when uninstalling from the command line. If the uninstall needs to be
	// retried the entire uninstall command can be retried. Retries may complete asynchronously with the
	// execution of the uninstall command, leading to bugs like https://github.com/elastic/elastic-agent/issues/3060.
	return comprt.UninstallService(ctx, log, comp, uninstallToken)
}

func serviceComponentsFromConfig(specs component.RuntimeSpecs, cfg *config.Config) ([]component.Component, error) {
	mm, err := cfg.ToMapStr()
	if err != nil {
		return nil, aerrors.New("failed to create a map from config", err)
	}
	allComps, err := specs.ToComponents(mm, nil, logp.InfoLevel, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to render components: %w", err)
	}
	var serviceComps []component.Component
	for _, comp := range allComps {
		if comp.Err == nil && comp.InputSpec != nil && comp.InputSpec.Spec.Service != nil {
			// non-error and service based component
			serviceComps = append(serviceComps, comp)
		}
	}
	return serviceComps, nil
}

func applyDynamics(ctx context.Context, log *logger.Logger, cfg *config.Config) (*config.Config, error) {
	cfgMap, err := cfg.ToMapStr()
	if err != nil {
		return nil, err
	}

	ast, err := transpiler.NewAST(cfgMap)
	if err != nil {
		return nil, err
	}

	// apply dynamic inputs
	inputs, ok := transpiler.Lookup(ast, "inputs")
	if ok {
		varsArray, err := vars.WaitForVariables(ctx, log, cfg, 0)
		if err != nil {
			return nil, err
		}

		renderedInputs, err := transpiler.RenderInputs(inputs, varsArray)
		if err != nil {
			return nil, err
		}
		err = transpiler.Insert(ast, renderedInputs, "inputs")
		if err != nil {
			return nil, aerrors.New("inserting rendered inputs failed", err)
		}
	}

	finalConfig, err := ast.Map()
	if err != nil {
		return nil, err
	}

	return config.NewConfigFrom(finalConfig)
}

// killWatcher finds and kills any running Elastic Agent watcher.
func killWatcher() error {
	procStats := process.Stats{
		Procs:        []string{".*elastic-agent"},
		CacheCmdLine: true,
	}
	err := procStats.Init()
	if err != nil {
		return fmt.Errorf("failed to initialize process.Stats: %w", err)
	}
	pidMap, _, err := procStats.FetchPids()
	if err != nil {
		return fmt.Errorf("failed to fetch elastic-agent pids: %w", err)
	}
	var errs error
	for pid, state := range pidMap {
		if len(state.Args) < 2 {
			// must have at least 2 args "elastic-agent watcher"
			continue
		}
		if filepath.Base(state.Args[0]) == "elastic-agent" && state.Args[1] == "watch" {
			// it is the watch subprocess
			proc, err := os.FindProcess(pid)
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to load watcher process with pid %d: %w", pid, err))
				continue
			}
			err = proc.Kill()
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to kill watcher process with pid %d: %w", pid, err))
				continue
			}
		}
	}
	return errs
}
