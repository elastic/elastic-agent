// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package artifact

import (
	"reflect"
	"runtime"
	"strings"
	"time"

	c "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	darwin  = "darwin"
	linux   = "linux"
	windows = "windows"

	// DefaultSourceURI is the default source URI for downloading artifacts.
	DefaultSourceURI = "https://artifacts.elastic.co/downloads/"
)

type ConfigReloader interface {
	Reload(*Config) error
}

// configWithoutHTTPTransportSettings is a copy of Config without
// httpcommon.HTTPTransportSettings so we can handle the  HTTPTransportSettings
// config separately during *Config.Unpack
type configWithoutHTTPTransportSettings struct {
	// OperatingSystem: operating system [linux, windows, darwin]
	OperatingSystem string `json:"-" config:",ignore"`

	// Architecture: target architecture [32, 64]
	Architecture string `json:"-" config:",ignore"`

	// SourceURI: source of the artifacts, e.g https://artifacts.elastic.co/downloads/
	SourceURI string `json:"sourceURI" config:"sourceURI"`

	// TargetDirectory: path to the directory containing downloaded packages
	TargetDirectory string `json:"targetDirectory" config:"target_directory"`

	// InstallPath: path to the directory containing installed packages
	InstallPath string `yaml:"installPath" config:"install_path"`

	// DropPath: path where elastic-agent can find installation files for download.
	// Difference between this and TargetDirectory is that when fetching packages (from web or fs) they are stored in TargetDirectory
	// DropPath specifies where Filesystem downloader can find packages which will then be placed in TargetDirectory. This can be
	// local or network disk.
	// If not provided FileSystem Downloader will fallback to /beats subfolder of elastic-agent directory.
	DropPath string `yaml:"dropPath" config:"drop_path"`

	// RetrySleepInitDuration: the duration to sleep for before the first retry attempt. This duration
	// will increase for subsequent retry attempts in a randomized exponential backoff manner.
	// This key is, for some reason, problematic
	RetrySleepInitDuration time.Duration `yaml:"retry_sleep_init_duration" config:"retry_sleep_init_duration"`
}

// Config is a configuration used for verifier and downloader
type Config struct {
	// OperatingSystem: operating system [linux, windows, darwin]
	OperatingSystem string `json:"-" config:",ignore"`

	// Architecture: target architecture [32, 64]
	Architecture string `json:"-" config:",ignore"`

	// SourceURI: source of the artifacts, e.g https://artifacts.elastic.co/downloads/
	SourceURI string `json:"sourceURI" config:"sourceURI"`

	// TargetDirectory: path to the directory containing downloaded packages
	TargetDirectory string `json:"targetDirectory" config:"target_directory"`

	// InstallPath: path to the directory containing installed packages
	InstallPath string `yaml:"installPath" config:"install_path"`

	// DropPath: path where elastic-agent can find installation files for download.
	// Difference between this and TargetDirectory is that when fetching packages (from web or fs) they are stored in TargetDirectory
	// DropPath specifies where Filesystem downloader can find packages which will then be placed in TargetDirectory. This can be
	// local or network disk.
	// If not provided FileSystem Downloader will fallback to /beats subfolder of elastic-agent directory.
	DropPath string `yaml:"dropPath" config:"drop_path"`

	// RetrySleepInitDuration: the duration to sleep for before the first retry attempt. This duration
	// will increase for subsequent retry attempts in a randomized exponential backoff manner.
	RetrySleepInitDuration time.Duration `yaml:"retry_sleep_init_duration" config:"retry_sleep_init_duration"`

	httpcommon.HTTPTransportSettings `config:",inline" yaml:",inline"` // Note: use anonymous struct for json inline
}

type Reloader struct {
	log       *logger.Logger
	cfg       *Config
	reloaders []ConfigReloader
}

func NewReloader(cfg *Config, log *logger.Logger, rr ...ConfigReloader) *Reloader {
	return &Reloader{
		cfg:       cfg,
		log:       log,
		reloaders: rr,
	}
}

func (r *Reloader) Reload(rawConfig *config.Config) error {
	if err := r.reloadConfig(rawConfig); err != nil {
		return errors.New(err, "failed to reload config")
	}

	if err := r.reloadSourceURI(rawConfig); err != nil {
		return errors.New(err, "failed to reload source URI")
	}

	for _, reloader := range r.reloaders {
		if err := reloader.Reload(r.cfg); err != nil {
			return errors.New(err, "failed reloading config")
		}
	}

	return nil
}

func (r *Reloader) reloadConfig(rawConfig *config.Config) error {
	type reloadConfig struct {
		C *Config `json:"agent.download" config:"agent.download"`
	}
	tmp := &reloadConfig{
		C: DefaultConfig(),
	}
	if err := rawConfig.UnpackTo(&tmp); err != nil {
		return err
	}

	*(r.cfg) = Config{
		OperatingSystem:       tmp.C.OperatingSystem,
		Architecture:          tmp.C.Architecture,
		SourceURI:             tmp.C.SourceURI,
		TargetDirectory:       tmp.C.TargetDirectory,
		InstallPath:           tmp.C.InstallPath,
		DropPath:              tmp.C.DropPath,
		HTTPTransportSettings: tmp.C.HTTPTransportSettings,
	}

	return nil
}

func (r *Reloader) reloadSourceURI(rawConfig *config.Config) error {
	type reloadConfig struct {
		// SourceURI: source of the artifacts, e.g https://artifacts.elastic.co/downloads/
		SourceURI string `json:"agent.download.sourceURI" config:"agent.download.sourceURI"`

		// FleetSourceURI: source of the artifacts, e.g https://artifacts.elastic.co/downloads/ coming from fleet which uses
		// different naming.
		FleetSourceURI string `json:"agent.download.source_uri" config:"agent.download.source_uri"`
	}
	cfg := &reloadConfig{}
	if err := rawConfig.UnpackTo(&cfg); err != nil {
		return errors.New(err, "failed to unpack config during reload")
	}

	var newSourceURI string
	if fleetURI := strings.TrimSpace(cfg.FleetSourceURI); fleetURI != "" {
		// fleet configuration takes precedence
		newSourceURI = fleetURI
	} else if sourceURI := strings.TrimSpace(cfg.SourceURI); sourceURI != "" {
		newSourceURI = sourceURI
	}

	if newSourceURI != "" {
		r.log.Infof("Source URI changed from %q to %q", r.cfg.SourceURI, newSourceURI)
		r.cfg.SourceURI = newSourceURI
	} else {
		// source uri unset, reset to default
		r.log.Infof("Source URI reset from %q to %q", r.cfg.SourceURI, DefaultSourceURI)
		r.cfg.SourceURI = DefaultSourceURI
	}

	return nil
}

// DefaultConfig creates a config with pre-set default values.
func DefaultConfig() *Config {
	transport := httpcommon.DefaultHTTPTransportSettings()

	// Elastic Agent binary is rather large and based on the network bandwidth it could take some time
	// to download the full file. 120 minutes is a very large value, but we really want it to finish.
	// The HTTP download will log progress in the case that it is taking a while to download.
	transport.Timeout = 120 * time.Minute

	return &Config{
		SourceURI:              DefaultSourceURI,
		TargetDirectory:        paths.Downloads(),
		InstallPath:            paths.Install(),
		RetrySleepInitDuration: 30 * time.Second,
		HTTPTransportSettings:  transport,
	}
}

// OS returns the configured operating system or falls back to runtime.GOOS
func (c *Config) OS() string {
	if c.OperatingSystem != "" {
		return c.OperatingSystem
	}

	switch runtime.GOOS {
	case windows:
		c.OperatingSystem = windows
	case darwin:
		c.OperatingSystem = darwin
	default:
		c.OperatingSystem = linux
	}

	return c.OperatingSystem
}

// Arch returns the configured architecture or falls back to 32bit
func (c *Config) Arch() string {
	if c.Architecture != "" {
		return c.Architecture
	}

	arch := "32"
	if strings.Contains(runtime.GOARCH, "arm64") {
		arch = "arm64"
	} else if strings.Contains(runtime.GOARCH, "64") {
		arch = "64"
	}

	c.Architecture = arch
	return c.Architecture
}

// Unpack reads a config object into the settings.
func (c *Config) Unpack(cfg *c.C) error {
	// c.HTTPTransportSettings need to be unpacked separately (see
	// https://github.com/elastic/elastic-agent/pull/776). Therefore, to ensure
	// we don't miss out any value, we'll use reflection to copy them all.
	// see https://go.dev/blog/laws-of-reflection to understand the reflection part.

	tmp := configWithoutHTTPTransportSettings{}

	cValue := reflect.ValueOf(c).Elem()
	tmpType := reflect.TypeOf(tmp)
	tmpValue := reflect.ValueOf(&tmp).Elem()

	// Copy all values of c to tmp. As Config has more fields than
	// configWithoutHTTPTransportSettings, we iterate over the fields of
	// configWithoutHTTPTransportSettings and for each field we get the value
	// of the field in c and set in tmp.
	// There is a test to ensure Config will always be a superset of
	// configWithoutHTTPTransportSettings.
	for i := 0; i < tmpType.NumField(); i++ {
		name := tmpType.Field(i).Name
		tmpField := tmpValue.FieldByName(name)

		if tmpField.IsValid() && tmpField.CanSet() {
			tmpField.Set(cValue.FieldByName(name))
		}
	}

	if err := cfg.Unpack(&tmp); err != nil {
		return err
	}

	transport := DefaultConfig().HTTPTransportSettings
	if err := cfg.Unpack(&transport); err != nil {
		return err
	}
	// HTTPTransportSettings.Proxy.Headers defaults to empty. If absent in cfg,
	// UnpackTo will set it to nil. To ensure consistency, we reset it to empty.
	if transport.Proxy.Headers == nil {
		transport.Proxy.Headers = map[string]string{}
	}

	// Now copy back all updated values of tmp to c.
	for i := 0; i < tmpType.NumField(); i++ {
		name := tmpType.Field(i).Name
		cField := cValue.FieldByName(name)

		if cField.IsValid() && cField.CanSet() {
			cField.Set(tmpValue.FieldByName(name))
		}
	}
	c.HTTPTransportSettings = transport

	return nil
}
