// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
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

	SetLevel(logp.InfoLevel)

	// core logger works
	require.Equal(t, false, l.Core().Enabled(zapcore.DebugLevel))
	require.Equal(t, true, l.Core().Enabled(zapcore.InfoLevel))
	require.Equal(t, true, l.Core().Enabled(zapcore.WarnLevel))
	require.Equal(t, true, l.Core().Enabled(zapcore.ErrorLevel))
	// enabler updated
	require.Equal(t, false, internalLevelEnabler.Enabled(zapcore.DebugLevel))
	require.Equal(t, true, internalLevelEnabler.Enabled(zapcore.InfoLevel))
	require.Equal(t, true, internalLevelEnabler.Enabled(zapcore.WarnLevel))
	require.Equal(t, true, internalLevelEnabler.Enabled(zapcore.ErrorLevel))

	SetLevel(logp.DebugLevel)

	// core logger works
	require.Equal(t, true, l.Core().Enabled(zapcore.DebugLevel))
	require.Equal(t, true, l.Core().Enabled(zapcore.InfoLevel))
	require.Equal(t, true, l.Core().Enabled(zapcore.WarnLevel))
	require.Equal(t, true, l.Core().Enabled(zapcore.ErrorLevel))
	// enabler updated
	require.Equal(t, true, internalLevelEnabler.Enabled(zapcore.DebugLevel))
	require.Equal(t, true, internalLevelEnabler.Enabled(zapcore.InfoLevel))
	require.Equal(t, true, internalLevelEnabler.Enabled(zapcore.WarnLevel))
	require.Equal(t, true, internalLevelEnabler.Enabled(zapcore.ErrorLevel))
}
