package loggertest

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// New creates a testing logger that buffers the logs in memory and
// logs in debug level. Check observer.ObservedLogs for more details.
func New(name string) (*logger.Logger, *observer.ObservedLogs) {
	core, obs := observer.New(zapcore.DebugLevel)

	log := logp.NewLogger(
		name,
		zap.WrapCore(func(in zapcore.Core) zapcore.Core {
			return zapcore.NewTee(in, core)
		}))

	return log, obs
}

// PrintObservedLogs consumes, formats and prints all log entries from obs,
// one at a time, printFn. It calls `observer.ObservedLogs.TakeAll`,
// therefore, after calling it, the ObservedLogs will be empty.
func PrintObservedLogs(obs *observer.ObservedLogs, printFn func(a ...any)) {
	rawLogs := obs.TakeAll()
	for _, rawLog := range rawLogs {
		msg := fmt.Sprintf("[%s] %s", rawLog.Level, rawLog.Message)
		for k, v := range rawLog.ContextMap() {
			msg += fmt.Sprintf(" %s=%v", k, v)
		}
		printFn(msg)
	}
}
