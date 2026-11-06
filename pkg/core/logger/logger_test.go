// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package logger

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent-libs/logp"
)

func Test_SetLevel(t *testing.T) {
	l, err := NewWithLogpLevel("", logp.ErrorLevel, true)
	require.NoError(t, err)

	// core logger works
	require.Equal(t, false, l.Core().Enabled(zapcore.DebugLevel))
	require.Equal(t, false, l.Core().Enabled(zapcore.InfoLevel))
	require.Equal(t, false, l.Core().Enabled(zapcore.WarnLevel))
	require.Equal(t, true, l.Core().Enabled(zapcore.ErrorLevel))
	// enabler updated
	require.Equal(t, false, internalLevelEnabler.Enabled(zapcore.DebugLevel))
	require.Equal(t, false, internalLevelEnabler.Enabled(zapcore.InfoLevel))
	require.Equal(t, false, internalLevelEnabler.Enabled(zapcore.WarnLevel))
	require.Equal(t, true, internalLevelEnabler.Enabled(zapcore.ErrorLevel))

	tests := []struct {
		SetLogLevel  logp.Level
		DebugEnabled bool
		InfoEnabled  bool
		WarnEnabled  bool
		ErrEnabled   bool
	}{
		{logp.DebugLevel, true, true, true, true},
		{logp.InfoLevel, false, true, true, true},
		{logp.WarnLevel, false, false, true, true},
		{logp.ErrorLevel, false, false, false, true},
	}

	for _, tc := range tests {
		SetLevel(tc.SetLogLevel)

		// core logger works
		require.Equal(t, tc.DebugEnabled, l.Core().Enabled(zapcore.DebugLevel))
		require.Equal(t, tc.InfoEnabled, l.Core().Enabled(zapcore.InfoLevel))
		require.Equal(t, tc.WarnEnabled, l.Core().Enabled(zapcore.WarnLevel))
		require.Equal(t, tc.ErrEnabled, l.Core().Enabled(zapcore.ErrorLevel))
		// enabler updated
		require.Equal(t, tc.DebugEnabled, internalLevelEnabler.Enabled(zapcore.DebugLevel))
		require.Equal(t, tc.InfoEnabled, internalLevelEnabler.Enabled(zapcore.InfoLevel))
		require.Equal(t, tc.WarnEnabled, internalLevelEnabler.Enabled(zapcore.WarnLevel))
		require.Equal(t, tc.ErrEnabled, internalLevelEnabler.Enabled(zapcore.ErrorLevel))
	}
}

func TestNewInMemory(t *testing.T) {
	log, buff := NewInMemory("in_memory", logp.ConsoleEncoderConfig())

	log.Debugw("a debug message", "debug_key", "debug_val")
	log.Infow("a info message", "info_key", "info_val")
	log.Warnw("a warn message", "warn_key", "warn_val")
	log.Errorw("an error message", "error_key", "error_val")

	logs := strings.Split(strings.TrimSpace(buff.String()), "\n")
	assert.Len(t, logs, 4, "expected 4 log entries")

	assert.Contains(t, logs[0], "a debug message")
	assert.Contains(t, logs[0], "debug_key")
	assert.Contains(t, logs[0], "debug_val")

	assert.Contains(t, logs[1], "a info message")
	assert.Contains(t, logs[1], "info_key")
	assert.Contains(t, logs[1], "info_val")

	assert.Contains(t, logs[2], "a warn message")
	assert.Contains(t, logs[2], "warn_key")
	assert.Contains(t, logs[2], "warn_val")

	assert.Contains(t, logs[3], "an error message")
	assert.Contains(t, logs[3], "error_key")
	assert.Contains(t, logs[3], "error_val")
}
