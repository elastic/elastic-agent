// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package config

import (
	"fmt"
	"io"
	"maps"
	"os"

	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/cfgutil"
)

func init() {
	tlscommon.SetInsecureDefaults()
}

// options hold the specified options
type options struct {
	otelKeys []string
	skipKeys []string
}

// Option is an option type that modifies how loading configs work
type Option func(*options)

// OTelKeys maps top-level keys to OTel specific configuration.
//
// The provided keys only skip if the keys are top-level keys.
func OTelKeys(keys ...string) Option {
	return func(opts *options) {
		opts.otelKeys = keys
	}
}

// VarSkipKeys prevents variable expansion for these keys.
//
// The provided keys only skip if the keys are top-level keys.
func VarSkipKeys(keys ...string) Option {
	return func(opts *options) {
		opts.skipKeys = keys
	}
}

// DefaultOptions defaults options used to read the configuration
var DefaultOptions = []interface{}{
	ucfg.PathSep("."),
	ucfg.ResolveEnv,
	ucfg.VarExp,
	VarSkipKeys("inputs", "outputs"),
	ucfg.IgnoreCommas,
	OTelKeys("connectors", "receivers", "processors", "exporters", "extensions", "service"),
}

// Config custom type that can provide both an Agent configuration alongside of an optional OTel configuration.
type Config struct {
	// Agent configuration
	Agent *ucfg.Config
	// OTel configuration (YAML bytes raw)
	OTel *confmap.Conf
}

// New creates a new empty config.
func New() *Config {
	return newConfigFrom(ucfg.New(), nil)
}

// NewConfigFrom takes a interface and read the configuration like it was YAML.
func NewConfigFrom(from interface{}, opts ...interface{}) (*Config, error) {
	if len(opts) == 0 {
		opts = DefaultOptions
	}
	ucfgOpts, local, err := getOptions(opts...)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if bytes, ok := from.([]byte); ok {
		err = yaml.Unmarshal(bytes, &data)
		if err != nil {
			return nil, err
		}
	} else if str, ok := from.(string); ok {
		err = yaml.Unmarshal([]byte(str), &data)
		if err != nil {
			return nil, err
		}
	} else if in, ok := from.(io.Reader); ok {
		if closer, ok := from.(io.Closer); ok {
			defer closer.Close()
		}
		fData, err := io.ReadAll(in)
		if err != nil {
			return nil, err
		}
		err = yaml.Unmarshal(fData, &data)
		if err != nil {
			return nil, err
		}
	} else if contents, ok := from.(map[string]interface{}); ok {
		// don't modify the incoming contents
		data = maps.Clone(contents)
	} else {
		c, err := ucfg.NewFrom(from, ucfgOpts...)
		return newConfigFrom(c, nil), err
	}

	otelKeys := map[string]interface{}{}
	for _, skip := range local.otelKeys {
		val, ok := data[skip]
		if ok {
			otelKeys[skip] = val
			delete(data, skip)
		}
	}

	skippedKeys := map[string]interface{}{}
	for _, skip := range local.skipKeys {
		val, ok := data[skip]
		if ok {
			skippedKeys[skip] = val
			delete(data, skip)
		}
	}
	cfg, err := ucfg.NewFrom(data, ucfgOpts...)
	if err != nil {
		return nil, err
	}
	if len(skippedKeys) > 0 {
		err = cfg.Merge(skippedKeys, ucfg.ResolveNOOP)
		if err != nil {
			return nil, err
		}
	}

	var otelCfg *confmap.Conf
	if len(otelKeys) > 0 {
		otelCfg = confmap.NewFromStringMap(otelKeys)
	}

	return newConfigFrom(cfg, otelCfg), nil
}

// MustNewConfigFrom try to create a configuration based on the type passed as arguments and panic
// on failures.
func MustNewConfigFrom(from interface{}) *Config {
	c, err := NewConfigFrom(from)
	if err != nil {
		panic(fmt.Sprintf("could not read configuration %+v", err))
	}
	return c
}

func newConfigFrom(in *ucfg.Config, otel *confmap.Conf) *Config {
	return &Config{
		Agent: in,
		OTel:  otel,
	}
}

// Unpack implements the ucfg.Unpacker interface.
func (c *Config) Unpack(val interface{}) error {
	if c.Agent == nil {
		c.Agent = ucfg.New()
	}
	return c.Agent.Merge(val)
}

// UnpackTo unpacks this config into to with the given options.
func (c *Config) UnpackTo(to interface{}, opts ...interface{}) error {
	ucfgOpts, _, err := getOptions(opts...)
	if err != nil {
		return err
	}
	return c.access().Unpack(to, ucfgOpts...)
}

func (c *Config) access() *ucfg.Config {
	return c.Agent
}

// Merge merges two configuration together.
func (c *Config) Merge(from interface{}, opts ...interface{}) error {
	ucfgOpts, _, err := getOptions(opts...)
	if err != nil {
		return err
	}
	cfg, ok := from.(*Config)
	if ok {
		// can merge both together
		err = c.access().Merge(cfg.Agent, ucfgOpts...)
		if err != nil {
			return err
		}
		if c.OTel == nil && cfg.OTel != nil {
			// simple, update to other retrieved configuration
			c.OTel = cfg.OTel
		} else if cfg.OTel != nil {
			err = c.OTel.Merge(cfg.OTel)
			if err != nil {
				return err
			}
		}
		return nil
	}
	return c.access().Merge(from, ucfgOpts...)
}

// ToMapStr takes the config and transform it into a map[string]interface{}
func (c *Config) ToMapStr(opts ...interface{}) (map[string]interface{}, error) {
	if len(opts) == 0 {
		opts = DefaultOptions
	}
	ucfgOpts, local, err := getOptions(opts...)
	if err != nil {
		return nil, fmt.Errorf("error unpacking config: %w", err)
	}
	// remove and unpack each skip keys into its own map with no resolve
	// so that variables are not substituted
	skippedKeys := map[string]interface{}{}
	skippedKeysOrig := map[string]*ucfg.Config{}
	for _, skip := range local.skipKeys {
		if c.access().HasField(skip) {
			subCfg, err := c.access().Child(skip, -1)
			if err != nil {
				return nil, fmt.Errorf("error accessing skip key %s: %w", skip, err)
			}
			var subUnpacked interface{}
			if subCfg.IsDict() {
				var subDict map[string]interface{}
				err = subCfg.Unpack(&subDict, ucfg.ResolveNOOP)
				if err != nil {
					return nil, fmt.Errorf("error unpacking subdict object in config for skip key %s: %w", skip, err)
				}
				subUnpacked = subDict
			} else if subCfg.IsArray() {
				var subArr []interface{}
				err = subCfg.Unpack(&subArr, ucfg.ResolveNOOP)
				if err != nil {
					return nil, fmt.Errorf("error unpacking subarray in config for skip key %s: %w ", skip, err)
				}
				subUnpacked = subArr
			} else {
				return nil, fmt.Errorf("unsupported type for SkipKeys option %s", skip)
			}
			_, err = c.access().Remove(skip, -1)
			if err != nil {
				return nil, fmt.Errorf("error removing skip key %s: %w", skip, err)
			}
			skippedKeys[skip] = subUnpacked
			skippedKeysOrig[skip] = subCfg
		}
	}

	// perform unpack with the skip keys removed
	var m map[string]interface{}
	if err := c.access().Unpack(&m, ucfgOpts...); err != nil {
		return nil, fmt.Errorf("error unpacking config to MapStr object: %w", err)
	}

	// add the skipped keys into the map and back into the config
	for k, v := range skippedKeys {
		m[k] = v
	}
	if len(skippedKeysOrig) > 0 {
		err := c.access().Merge(skippedKeysOrig, ucfg.ResolveNOOP)
		if err != nil {
			return nil, fmt.Errorf("error merging config with skipped key config: %w", err)
		}
	}
	return m, nil
}

// Enabled return the configured enabled value or true by default.
func (c *Config) Enabled() bool {
	testEnabled := struct {
		Enabled bool `config:"enabled"`
	}{true}

	if c == nil {
		return false
	}
	if err := c.UnpackTo(&testEnabled); err != nil {
		// if unpacking fails, expect 'enabled' being set to default value
		return true
	}
	return testEnabled.Enabled
}

// LoadFile take a path and load the file and return a new configuration.
func LoadFile(path string) (*Config, error) {
	fp, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return NewConfigFrom(fp)
}

// LoadFiles takes multiples files, load and merge all of them in a single one.
func LoadFiles(paths ...string) (*Config, error) {
	merger := cfgutil.NewCollector(nil)
	for _, path := range paths {
		cfg, err := LoadFile(path)
		if err := merger.Add(cfg.access(), err); err != nil {
			return nil, err
		}
	}
	return newConfigFrom(merger.Config(), nil), nil
}

func getOptions(opts ...interface{}) ([]ucfg.Option, options, error) {
	if len(opts) == 0 {
		opts = DefaultOptions
	}
	var ucfgOpts []ucfg.Option
	var localOpts []Option
	var local options
	for _, o := range opts {
		switch ot := o.(type) {
		case ucfg.Option:
			ucfgOpts = append(ucfgOpts, ot)
		case Option:
			localOpts = append(localOpts, ot)
		default:
			return nil, local, fmt.Errorf("unknown option type %T", o)
		}
	}
	for _, o := range localOpts {
		o(&local)
	}
	return ucfgOpts, local, nil
}
