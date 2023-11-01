// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.elastic.co/ecszap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/file"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/logp/configure"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const agentName = "elastic-agent"

const iso8601Format = "2006-01-02T15:04:05.000Z0700"

// Level is the level used in agent.
type Level = logp.Level

// DefaultLogLevel used in agent and its processes.
const DefaultLogLevel = logp.InfoLevel

// DefaultLogDirectory used in agent and its processes.
const DefaultLogDirectory = "logs"

// Logger alias ecslog.Logger with Logger.
type Logger = logp.Logger

// Config is a logging config.
type Config = logp.Config

var internalLevelEnabler *zap.AtomicLevel

// New returns a configured ECS Logger
func New(name string, logInternal bool) (*Logger, error) {
	defaultCfg := DefaultLoggingConfig()
	return new(name, defaultCfg, logInternal)
}

// NewWithLogpLevel returns a configured logp Logger with specified level.
func NewWithLogpLevel(name string, level logp.Level, logInternal bool) (*Logger, error) {
	defaultCfg := DefaultLoggingConfig()
	defaultCfg.Level = level

	return new(name, defaultCfg, logInternal)
}

// NewFromConfig takes the user configuration and generate the right logger.
// We should finish implementation, need support on the library that we use.
func NewFromConfig(name string, cfg *Config, logInternal bool) (*Logger, error) {
	return new(name, cfg, logInternal)
}

// NewWithoutConfig returns a new logger without having a configuration.
//
// Use only when a clean logger is needed, and it is known that the logging configuration has already been performed.
func NewWithoutConfig(name string) *Logger {
	return logp.NewLogger(name)
}

// AddCallerSkip returns new logger with incremented stack frames to skip.
// This is needed in order to correctly report the log file lines when the logging statement
// is wrapped in some convenience wrapping function for example.
func AddCallerSkip(l *Logger, skip int) *Logger {
	return l.WithOptions(zap.AddCallerSkip(skip))
}

func new(name string, cfg *Config, logInternal bool) (*Logger, error) {
	commonCfg, err := ToCommonConfig(cfg)
	if err != nil {
		return nil, err
	}

	var outputs []zapcore.Core
	if logInternal {
		internal, err := MakeInternalFileOutput(cfg)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, internal)
	}

	if err := configure.LoggingWithOutputs("", commonCfg, outputs...); err != nil {
		return nil, fmt.Errorf("error initializing logging: %w", err)
	}
	return logp.NewLogger(name), nil
}

func ToCommonConfig(cfg *Config) (*config.C, error) {
	// work around custom types and common config
	// when custom type is transformed to common.Config
	// value is determined based on reflect value which is incorrect
	// enum vs human readable form
	yamlCfg, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	commonLogp, err := config.NewConfigFrom(string(yamlCfg))
	if err != nil {
		return nil, errors.New(err, errors.TypeConfig)
	}

	return commonLogp, nil
}

// SetLevel changes the overall log level of the global logger.
func SetLevel(lvl logp.Level) {
	zapLevel := lvl.ZapLevel()
	logp.SetLevel(zapLevel)
	if internalLevelEnabler != nil {
		internalLevelEnabler.SetLevel(zapLevel)
	}
}

// DefaultLoggingConfig returns default configuration for agent logging.
func DefaultLoggingConfig() *Config {
	cfg := logp.DefaultConfig(logp.DefaultEnvironment)
	cfg.Beat = agentName
	cfg.Level = DefaultLogLevel
	cfg.ToFiles = true
	cfg.Files.Path = paths.Logs()
	cfg.Files.Name = agentName
	cfg.Files.MaxSize = 20 * 1024 * 1024
	cfg.Files.Permissions = 0600 // default user only
	root, _ := utils.HasRoot()   // error ignored
	if !root {
		// when not running as root, the default changes to include the group
		cfg.Files.Permissions = 0660
	}

	return &cfg
}

// makeInternalFileOutput creates a zapcore.Core logger that cannot be changed with configuration.
//
// This is the logger that the spawned filebeat expects to read the log file from and ship to ES.
func MakeInternalFileOutput(cfg *Config) (zapcore.Core, error) {
	// defaultCfg is used to set the defaults for the file rotation of the internal logging
	// these settings cannot be changed by a user configuration
	defaultCfg := logp.DefaultConfig(logp.DefaultEnvironment)
	filename := filepath.Join(paths.Home(), DefaultLogDirectory, cfg.Beat)
	al := zap.NewAtomicLevelAt(cfg.Level.ZapLevel())
	internalLevelEnabler = &al // directly persisting struct will panic on accessing unitialized backing pointer
	rotator, err := file.NewFileRotator(filename,
		file.MaxSizeBytes(defaultCfg.Files.MaxSize),
		file.MaxBackups(defaultCfg.Files.MaxBackups),
		file.Permissions(os.FileMode(defaultCfg.Files.Permissions)),
		file.Interval(defaultCfg.Files.Interval),
		file.RotateOnStartup(defaultCfg.Files.RotateOnStartup),
		file.RedirectStderr(defaultCfg.Files.RedirectStderr),
	)
	if err != nil {
		return nil, errors.New("failed to create internal file rotator")
	}

	encoderConfig := ecszap.ECSCompatibleEncoderConfig(logp.JSONEncoderConfig())
	encoderConfig.EncodeTime = UtcTimestampEncode
	encoder := zapcore.NewJSONEncoder(encoderConfig)
	return ecszap.WrapCore(zapcore.NewCore(encoder, rotator, internalLevelEnabler)), nil
}

// UtcTimestampEncode is a zapcore.TimeEncoder that formats time.Time in ISO-8601 in UTC.
func UtcTimestampEncode(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	type appendTimeEncoder interface {
		AppendTimeLayout(time.Time, string)
	}
	if enc, ok := enc.(appendTimeEncoder); ok {
		enc.AppendTimeLayout(t.UTC(), iso8601Format)
		return
	}
	enc.AppendString(t.UTC().Format(iso8601Format))
}
