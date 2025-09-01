// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ghodss/yaml"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	requestRetrySleepEnv     = "KIBANA_REQUEST_RETRY_SLEEP"
	maxRequestRetriesEnv     = "KIBANA_REQUEST_RETRY_COUNT"
	defaultRequestRetrySleep = "1s"                       // sleep 1 sec between retries for HTTP requests
	defaultMaxRequestRetries = "30"                       // maximum number of retries for HTTP requests
	agentBaseDirectory       = "/usr/share/elastic-agent" // directory that holds all elastic-agent related files

	logsPathPerms = 0775
)

type ContainerPaths struct {
	StatePath  string `config:"state_path" yaml:"state_path"`
	ConfigPath string `config:"config_path" yaml:"config_path,omitempty"`
	LogsPath   string `config:"logs_path" yaml:"logs_path,omitempty"`
	SocketPath string `config:"socket_path" yaml:"socket_path,omitempty"`
}

func TryContainerLoadPaths() error {
	statePath := EnvWithDefault("", "STATE_PATH")
	if statePath == "" {
		statePath = DefaultStateDirectory
	}
	pathFile := filepath.Join(statePath, "container-paths.yml")
	_, err := os.Stat(pathFile)
	if os.IsNotExist(err) {
		// no container-paths.yml file exists, so nothing to do
		return nil
	}
	cfg, err := config.LoadFile(pathFile)
	if err != nil {
		return fmt.Errorf("failed to load %s: %w", pathFile, err)
	}
	var paths ContainerPaths
	err = cfg.UnpackTo(&paths)
	if err != nil {
		return fmt.Errorf("failed to unpack %s: %w", pathFile, err)
	}
	return SetPaths(paths.StatePath, paths.ConfigPath, paths.LogsPath, paths.SocketPath, false)
}

func SetPaths(statePath, configPath, logsPath, socketPath string, writePaths bool) error {
	statePath = EnvWithDefault(statePath, "STATE_PATH")
	if statePath == "" {
		statePath = DefaultStateDirectory
	}

	topPath := filepath.Join(statePath, "data")
	configPath = EnvWithDefault(configPath, "CONFIG_PATH")
	if configPath == "" {
		configPath = statePath
	}
	if _, err := os.Stat(configPath); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(configPath, 0755); err != nil {
			return fmt.Errorf("cannot create folders for config path '%s': %w", configPath, err)
		}
	}

	if socketPath == "" {
		socketPath = utils.SocketURLWithFallback(statePath, topPath)
	}
	// ensure that the directory and sub-directory data exists
	if err := os.MkdirAll(topPath, 0755); err != nil {
		return fmt.Errorf("preparing STATE_PATH(%s) failed: %w", statePath, err)
	}
	// ensure that the elastic-agent.yml exists in the state directory or if given in the config directory
	baseConfig := filepath.Join(configPath, paths.DefaultConfigName)
	if _, err := os.Stat(baseConfig); os.IsNotExist(err) {
		if err := copyFile(baseConfig, paths.ConfigFile(), 0); err != nil {
			return err
		}
	}

	originalInstall := paths.Install()
	paths.SetTop(topPath)
	paths.SetConfig(configPath)
	paths.SetControlSocket(socketPath)
	// when custom top path is provided the home directory is not versioned
	paths.SetVersionHome(false)
	// install path stays on container default mount (otherwise a bind mounted directory could have noexec set)
	paths.SetInstall(originalInstall)
	// set LOGS_PATH is given
	logsPath = EnvWithDefault(logsPath, "LOGS_PATH")
	if logsPath != "" {
		paths.SetLogs(logsPath)
		// ensure that the logs directory exists
		if err := os.MkdirAll(filepath.Join(logsPath), logsPathPerms); err != nil {
			return fmt.Errorf("preparing LOGS_PATH(%s) failed: %w", logsPath, err)
		}
	}

	// ensure that the internal logger directory exists
	loggerPath := filepath.Join(paths.Home(), logger.DefaultLogDirectory)
	if err := os.MkdirAll(loggerPath, logsPathPerms); err != nil {
		return fmt.Errorf("preparing internal log path(%s) failed: %w", loggerPath, err)
	}

	// persist the paths so other commands in the container will use the correct paths
	if writePaths {
		if err := writeContainerPaths(statePath, configPath, logsPath, socketPath); err != nil {
			return err
		}
	}
	return nil
}

func writeContainerPaths(statePath, configPath, logsPath, socketPath string) error {
	pathFile := filepath.Join(statePath, "container-paths.yml")
	fp, err := os.Create(pathFile)
	if err != nil {
		return fmt.Errorf("failed creating %s: %w", pathFile, err)
	}
	b, err := yaml.Marshal(ContainerPaths{
		StatePath:  statePath,
		ConfigPath: configPath,
		LogsPath:   logsPath,
		SocketPath: socketPath,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal for %s: %w", pathFile, err)
	}
	_, err = fp.Write(b)
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", pathFile, err)
	}
	return nil
}

func copyFile(destPath string, srcPath string, mode os.FileMode) error {
	// if mode is unset; set to the same as the source file
	if mode == 0 {
		info, err := os.Stat(srcPath)
		if err == nil {
			// ignoring error because; os.Open will also error if the file cannot be stat'd
			mode = info.Mode()
		}
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dest, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer dest.Close()
	_, err = io.Copy(dest, src)
	return err
}
