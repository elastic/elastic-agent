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
	"github.com/schollz/progressbar/v3"

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
	"github.com/elastic/elastic-agent/pkg/utils"
)

// Uninstall uninstalls persistently Elastic Agent on the system.
func Uninstall(cfgFile, topPath, uninstallToken string, pt *progressbar.ProgressBar) error {
	// uninstall the current service
	// not creating the service, so no need to set the username and group to any value
	svc, err := newService(topPath)
	if err != nil {
		return fmt.Errorf("error creating new service handler: %w", err)
	}
	status, _ := svc.Status()

	pt.Describe("Stopping service")
	if status == service.StatusRunning {
		err := svc.Stop()
		if err != nil {
			pt.Describe("Failed to stop service")
			return aerrors.New(
				err,
				fmt.Sprintf("failed to stop service (%s)", paths.ServiceName),
				aerrors.M("service", paths.ServiceName))
		}
	}
	pt.Describe("Successfully stopped service")

	// kill any running watcher
	if err := killWatcher(pt); err != nil {
		return fmt.Errorf("failed trying to kill any running watcher: %w", err)
	}

	// Uninstall components first
	if err := uninstallComponents(context.Background(), cfgFile, uninstallToken, pt); err != nil {
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
		return fmt.Errorf("error uninstalling components: %w", err)
	}

	// Uninstall service only after components were uninstalled successfully
	pt.Describe("Removing service")
	err = svc.Uninstall()
	// Is there a reason why we don't want to hard-fail on this?
	if err != nil {
		pt.Describe(fmt.Sprintf("Failed to Uninstall existing service: %s", err))
	} else {
		pt.Describe("Successfully uninstalled service")
	}

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
	pt.Describe("Removing install directory")
	err = RemovePath(topPath)
	if err != nil {
		pt.Describe("Failed to remove install directory")
		return aerrors.New(
			err,
			fmt.Sprintf("failed to remove installation directory (%s)", paths.Top()),
			aerrors.M("directory", paths.Top()))
	}
	pt.Describe("Removed install directory")

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
	var lastErr error
	for time.Since(start) <= arbitraryTimeout {
		lastErr = os.RemoveAll(path)

		if lastErr == nil || !isRetryableError(lastErr) {
			return lastErr
		}

		if isBlockingOnExe(lastErr) {
			// try to remove the blocking exe and try again to clean up the path
			_ = removeBlockingExe(lastErr)
		}

		time.Sleep(50 * time.Millisecond)
	}

	return fmt.Errorf("timed out while removing %q. Last error: %w", path, lastErr)
}

func RemoveBut(path string, bestEffort bool, exceptions ...string) error {
	if len(exceptions) == 0 {
		return RemovePath(path)
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("error reading directory %s: %w", path, err)
	}

	for _, f := range files {
		if containsString(f.Name(), exceptions, runtime.GOOS != component.Windows) {
			continue
		}

		err = RemovePath(filepath.Join(path, f.Name()))
		if !bestEffort && err != nil {
			return fmt.Errorf("error removing path %s: %w", f.Name(), err)
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

func uninstallComponents(ctx context.Context, cfgFile string, uninstallToken string, pt *progressbar.ProgressBar) error {
	log, err := logger.NewWithLogpLevel("", logp.ErrorLevel, false)
	if err != nil {
		return fmt.Errorf("error creating logger: %w", err)
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
		return fmt.Errorf("error loading agent config: %w", err)
	}

	cfg, err = applyDynamics(ctx, log, cfg)
	if err != nil {
		return fmt.Errorf("error applying dynamic inputs: %w", err)
	}

	comps, err := serviceComponentsFromConfig(specs, cfg)
	if err != nil {
		return fmt.Errorf("error creating service components: %w", err)
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
		return fmt.Errorf("error checking capabilities: %w", err)
	}

	// remove each service component
	for _, comp := range comps {
		if !caps.AllowInput(comp.InputType) || !caps.AllowOutput(comp.OutputType) {
			// This component is not active
			continue
		}
		if err := uninstallServiceComponent(ctx, log, comp, uninstallToken, pt); err != nil {
			os.Stderr.WriteString(fmt.Sprintf("failed to uninstall component %q: %s\n", comp.ID, err))
			// The decision was made to change the behaviour and leave the Agent installed if Endpoint uninstall fails
			// https://github.com/elastic/elastic-agent/pull/2708#issuecomment-1574251911
			// Thus returning error here.
			return fmt.Errorf("error uninstalling component: %w", err)
		}
	}

	return nil
}

func uninstallServiceComponent(ctx context.Context, log *logp.Logger, comp component.Component, uninstallToken string, pt *progressbar.ProgressBar) error {
	// Do not use infinite retries when uninstalling from the command line. If the uninstall needs to be
	// retried the entire uninstall command can be retried. Retries may complete asynchronously with the
	// execution of the uninstall command, leading to bugs like https://github.com/elastic/elastic-agent/issues/3060.
	pt.Describe(fmt.Sprintf("Uninstalling service component %s", comp.InputType))
	err := comprt.UninstallService(ctx, log, comp, uninstallToken)
	if err != nil {
		pt.Describe("Failed to uninstall service")
		return fmt.Errorf("error uninstalling service: %w", err)
	}
	pt.Describe("Uninstalled service")
	return nil
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
func killWatcher(pt *progressbar.ProgressBar) error {
	for {
		// finding and killing watchers is performed in a loop until no
		// more watchers are existing, this ensures that during uninstall
		// that no matter what the watchers are dead before going any further
		pids, err := utils.GetWatcherPIDs()
		if err != nil {
			pt.Describe("Failed to get watcher PID")
			return fmt.Errorf("error fetching watcher PIDs: %w", err)
		}
		if len(pids) == 0 {
			// step was never started so no watcher was found on first loop
			pt.Describe("Stopping upgrade watcher; none found")
			return nil
		}

		var pidsStr []string
		for _, pid := range pids {
			pidsStr = append(pidsStr, fmt.Sprintf("%d", pid))
		}
		pt.Describe(fmt.Sprintf("Stopping upgrade watcher (%s)", strings.Join(pidsStr, ", ")))

		var errs error
		for _, pid := range pids {
			proc, err := os.FindProcess(pid)
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to load watcher process with pid %d: %w", pid, err))
				continue
			}
			err = proc.Kill()
			if err != nil && !errors.Is(err, os.ErrProcessDone) {
				errs = errors.Join(errs, fmt.Errorf("failed to kill watcher process with pid %d: %w", pid, err))
				continue
			}
		}
		if errs != nil {
			pt.Describe("Failed to find and stop watcher processes")
			return errs
		}
		// wait 1 second before performing the loop again
		<-time.After(1 * time.Second)
	}
}
