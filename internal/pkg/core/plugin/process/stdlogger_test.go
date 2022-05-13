package process

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func Test_loggerWriter(t *testing.T) {
	tc := []struct {
		name string
		args struct {
			appName string
			logTo   logStd
		}
		logMsg   string
		logLevel zapcore.Level
	}{
		{name: "capture stdout",
			args: struct {
				appName string
				logTo   logStd
			}{
				appName: "somebeats",
				logTo:   logStdOut,
			},
			logMsg:   "stdout log",
			logLevel: zapcore.InfoLevel,
		},
		{name: "capture stderr",
			args: struct {
				appName string
				logTo   logStd
			}{
				appName: "somebeats",
				logTo:   logStdErr,
			},
			logMsg:   "stderr log",
			logLevel: zapcore.ErrorLevel,
		},
	}

	for _, tt := range tc {
		logg, obs := logger.NewTesting("test-loggerWriter")
		logg = logg.With("previous-field", "previous-value")

		l := newLoggerWriter(tt.args.appName, tt.args.logTo, logg)
		_, _ = l.Write([]byte(tt.logMsg))

		logs := obs.All()
		require.Equal(t, 1, len(logs))

		log := logs[0]
		assert.Equal(t, log.Level, tt.logLevel)
		assert.Contains(t, log.Message, tt.logMsg)
		assert.Equal(t, log.ContextMap()[agentConsoleName], tt.args.appName)
		assert.Equal(t, log.ContextMap()[agentConsoleType], tt.args.logTo.String())
		assert.Equal(t, log.ContextMap()["previous-field"], "previous-value")
	}
}
