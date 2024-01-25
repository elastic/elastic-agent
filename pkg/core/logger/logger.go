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
	return new(name, defaultCfg, nil, logInternal)
}

// NewWithLogpLevel returns a configured logp Logger with specified level.
func NewWithLogpLevel(name string, level logp.Level, logInternal bool) (*Logger, error) {
	defaultCfg := DefaultLoggingConfig()
	defaultCfg.Level = level

	sensitiveConfig := DefaultSensitiveLoggingConfig()
	sensitiveConfig.Level = level

	return new(name, defaultCfg, sensitiveConfig, logInternal)
}

// NewFromConfig takes the user configuration and generate the right logger.
// The returned logger will have two outputs:
//   - One output following the settings from `loggerCfg`
//   - An internal file output that uses the defaults from `logp.DefaultConfig`
//     and cannot be configured. This outputs logs to `data/elastic-agent-<hash>/logs`
func NewFromConfig(name string, loggerCfg, sensitiveLoggerCfg *Config, logInternal bool) (*Logger, error) {
	return new(name, loggerCfg, sensitiveLoggerCfg, logInternal)
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

// new creates a new logger from the provided configurations.
//
// If `sensitiveLoggerCfg` is not nil, a core is created from it and added to
// to the logger. If `logInternal` is true, a core logging to
// `data/elastic-agent-<hash>/logs` is also created and added to the logger.
// This core uses the defaults from logp.DefaultConfig and cannot be configured.
func new(name string, LoggerCfg, sensitiveLoggerCfg *Config, logInternal bool) (*Logger, error) {
	commonCfg, err := ToCommonConfig(LoggerCfg)
	if err != nil {
		return nil, err
	}

	var outputs []zapcore.Core
	if logInternal {
		internal, err := MakeInternalFileOutput(LoggerCfg.Beat, LoggerCfg.Level)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, internal)
	}

	sensitiveCfg, err := ToCommonConfig(sensitiveLoggerCfg)
	if err != nil {
		return nil, fmt.Errorf("could not convert sensitive logger config: %w", err)
	}

	if err := configure.LoggingWithTypedOutputs("", commonCfg, sensitiveCfg, "log.type", "sensitive", outputs...); err != nil {
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

// DefaultLoggingConfig returns default configuration for agent logging.
func DefaultSensitiveLoggingConfig() *Config {
	cfg := logp.DefaultConfig(logp.DefaultEnvironment)
	cfg.Beat = agentName
	cfg.Level = DefaultLogLevel
	cfg.ToFiles = true
	// That's the same path useb by MakeInternalFileOutput
	cfg.Files.Path = filepath.Join(paths.Home(), DefaultLogDirectory)
	cfg.Files.Name = agentName + "-sensitive"
	cfg.Files.MaxSize = 5 * 1024 * 1024
	cfg.Files.MaxBackups = 2
	cfg.Files.Permissions = 0600 // default user only
	cfg.Files.RedirectStderr = false
	root, _ := utils.HasRoot() // error ignored
	if !root {
		// when not running as root, the default changes to include the group
		cfg.Files.Permissions = 0660
	}

	return &cfg
}

// makeInternalFileOutput creates a zapcore.Core logger that cannot be changed with configuration.
//
// This is the logger that the spawned filebeat expects to read the log file from and ship to ES.
func MakeInternalFileOutput(beatName string, level logp.Level) (zapcore.Core, error) {
	// defaultCfg is used to set the defaults for the file rotation of the internal logging
	// these settings cannot be changed by a user configuration
	defaultCfg := logp.DefaultConfig(logp.DefaultEnvironment)
	filename := filepath.Join(paths.Home(), DefaultLogDirectory, beatName)
	al := zap.NewAtomicLevelAt(level.ZapLevel())
	internalLevelEnabler = &al // directly persisting struct will panic on accessing unitialized backing pointer
	permissions := 0600        // default user only
	root, _ := utils.HasRoot() // error ignored
	if !root {
		// when not running as root, the default changes to include the group
		permissions = 0660
	}
	rotator, err := file.NewFileRotator(filename,
		file.MaxSizeBytes(defaultCfg.Files.MaxSize),
		file.MaxBackups(defaultCfg.Files.MaxBackups),
		file.Permissions(os.FileMode(permissions)),
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

// MakeFileOutput creates a new file output from the provided configuration.
// The created output writes logs in JSON compatible with ECS
func MakeFileOutput(cfg logp.Config) (zapcore.Core, error) {
	filename := filepath.Join(cfg.Files.Path, cfg.Files.Name)
	al := zap.NewAtomicLevelAt(cfg.Level.ZapLevel())
	internalLevelEnabler = &al // directly persisting struct will panic on accessing unitialized backing pointer
	permissions := 0600        // default user only
	root, _ := utils.HasRoot() // error ignored
	if !root {
		// when not running as root, the default changes to include the group
		permissions = 0660
	}
	rotator, err := file.NewFileRotator(filename,
		file.MaxSizeBytes(cfg.Files.MaxSize),
		file.MaxBackups(cfg.Files.MaxBackups),
		file.Permissions(os.FileMode(permissions)),
		file.Interval(cfg.Files.Interval),
		file.RotateOnStartup(cfg.Files.RotateOnStartup),
		file.RedirectStderr(false),
	)
	if err != nil {
		return nil, errors.New("failed to create file rotator")
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
