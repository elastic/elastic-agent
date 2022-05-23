package process

import (
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type logStd int

const (
	agentConsoleName = "agent.console.name"
	agentConsoleType = "agent.console.type"

	logStdOut logStd = iota
	logStdErr
)

func (l logStd) String() string {
	switch l {
	case logStdOut:
		return "stdout"
	case logStdErr:
		return "stderr"
	}

	return "unknown"
}

type loggerWriter struct {
	format string
	logf   func(format string, args ...interface{})
}

func newLoggerWriter(appName string, std logStd, log *logger.Logger) loggerWriter {
	log = log.With(
		agentConsoleName, appName,
		agentConsoleType, std.String())

	logf := log.Infof
	if std == logStdErr {
		logf = log.Errorf
	}

	return loggerWriter{
		format: appName + " " + std.String() + ": %q",
		logf:   logf,
	}
}

func (l loggerWriter) Write(p []byte) (n int, err error) {
	l.logf(l.format, string(p))
	return len(p), nil
}
