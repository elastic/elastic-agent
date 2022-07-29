// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kardianos/service"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/config/operations"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Uninstall uninstalls persistently Elastic Agent on the system.
func Uninstall(cfgFile string) error {
	// uninstall the current service
	svc, err := newService()
	if err != nil {
		return err
	}
	status, _ := svc.Status()
	if status == service.StatusRunning {
		err := svc.Stop()
		if err != nil {
			return errors.New(
				err,
				fmt.Sprintf("failed to stop service (%s)", paths.ServiceName),
				errors.M("service", paths.ServiceName))
		}
	}
	_ = svc.Uninstall()

	if err := uninstallComponents(context.Background(), cfgFile); err != nil {
		return err
	}

	// remove, if present on platform
	if paths.ShellWrapperPath != "" {
		err = os.Remove(paths.ShellWrapperPath)
		if !os.IsNotExist(err) && err != nil {
			return errors.New(
				err,
				fmt.Sprintf("failed to remove shell wrapper (%s)", paths.ShellWrapperPath),
				errors.M("destination", paths.ShellWrapperPath))
		}
	}

	// remove existing directory
	err = os.RemoveAll(paths.InstallPath)
	if err != nil {
		if runtime.GOOS == "windows" { //nolint:goconst // it is more readable this way
			// possible to fail on Windows, because elastic-agent.exe is running from
			// this directory.
			return nil
		}
		return errors.New(
			err,
			fmt.Sprintf("failed to remove installation directory (%s)", paths.InstallPath),
			errors.M("directory", paths.InstallPath))
	}

	return nil
}

// RemovePath helps with removal path where there is a probability
// of running into self which might prevent removal.
// Removal will be initiated 2 seconds after a call.
func RemovePath(path string) error {
	cleanupErr := os.RemoveAll(path)
	if cleanupErr != nil && isBlockingOnSelf(cleanupErr) {
		delayedRemoval(path)
	}

	return cleanupErr
}

func isBlockingOnSelf(err error) bool {
	// cannot remove self, this is expected on windows
	// fails with  remove {path}}\elastic-agent.exe: Access is denied
	return runtime.GOOS == "windows" &&
		err != nil &&
		strings.Contains(err.Error(), "elastic-agent.exe") &&
		strings.Contains(err.Error(), "Access is denied")
}

func delayedRemoval(path string) {
	// The installation path will still exists because we are executing from that
	// directory. So cmd.exe is spawned that sleeps for 2 seconds (using ping, recommend way from
	// from Windows) then rmdir is performed.
	//nolint:gosec // it's not tainted
	rmdir := exec.Command(
		filepath.Join(os.Getenv("windir"), "system32", "cmd.exe"),
		"/C", "ping", "-n", "2", "127.0.0.1", "&&", "rmdir", "/s", "/q", path)
	_ = rmdir.Start()

}

func uninstallComponents(ctx context.Context, cfgFile string) error {
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

	cfg, err := operations.LoadFullAgentConfig(log, cfgFile, false)
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

	// remove each service component
	for _, comp := range comps {
		if err := uninstallComponent(ctx, comp); err != nil {
			os.Stderr.WriteString(fmt.Sprintf("failed to uninstall component %q: %s\n", comp.ID, err))
		}
	}

	return nil
}

func uninstallComponent(_ context.Context, _ component.Component) error {
	// TODO(blakerouse): Perform uninstall of service component; once the service runtime is written.
	return errors.New("failed to uninstall component; not implemented")
}

func serviceComponentsFromConfig(specs component.RuntimeSpecs, cfg *config.Config) ([]component.Component, error) {
	mm, err := cfg.ToMapStr()
	if err != nil {
		return nil, errors.New("failed to create a map from config", err)
	}
	allComps, err := specs.ToComponents(mm)
	if err != nil {
		return nil, fmt.Errorf("failed to render components: %w", err)
	}
	var serviceComps []component.Component
	for _, comp := range allComps {
		if comp.Err == nil && comp.Spec.Spec.Service != nil {
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
		varsArray := make([]*transpiler.Vars, 0)

		ctrl, err := composable.New(log, cfg)
		if err != nil {
			return nil, err
		}
		_ = ctrl.Run(ctx)

		renderedInputs, err := transpiler.RenderInputs(inputs, varsArray)
		if err != nil {
			return nil, err
		}
		err = transpiler.Insert(ast, renderedInputs, "inputs")
		if err != nil {
			return nil, errors.New("inserting rendered inputs failed", err)
		}
	}

	// apply caps
	caps, err := capabilities.Load(paths.AgentCapabilitiesPath(), log)
	if err != nil {
		return nil, err
	}

	astIface, err := caps.Apply(ast)
	if err != nil {
		return nil, err
	}

	newAst, ok := astIface.(*transpiler.AST)
	if ok {
		ast = newAst
	}

	finalConfig, err := ast.Map()
	if err != nil {
		return nil, err
	}

	return config.NewConfigFrom(finalConfig)
}
