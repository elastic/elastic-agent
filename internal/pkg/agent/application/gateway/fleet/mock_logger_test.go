// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"fmt"
	"strings"
	"testing"
)

type logLevel uint

const (
	DEBUG logLevel = iota
	INFO
	WARN
	ERROR
)

type logMessage struct {
	lvl  logLevel
	msg  string
	args []any
}

func (lm logMessage) String() string {
	var sb strings.Builder
	switch lm.lvl {
	case DEBUG:
		sb.WriteString("DEBUG -")
	case INFO:
		sb.WriteString("INFO -")
	case WARN:
		sb.WriteString("WARN -")
	case ERROR:
		sb.WriteString("ERROR -")
	}

	if lm.msg != "" {
		sb.WriteString(" #MSG: ")
		sb.WriteString(fmt.Sprintf(lm.msg, lm.args...))
	}

	if len(lm.args) > 0 {
		sb.WriteString(fmt.Sprintf(" #ARGS: %#v", lm.args))
	}

	return sb.String()
}

type testlogger struct {
	t    *testing.T
	logs []logMessage
}

func (tl *testlogger) handleLog(lm logMessage) {
	tl.t.Helper()
	tl.logs = append(tl.logs, lm)
	tl.t.Logf("testlogger - %s", lm)
}

func (tl *testlogger) Debug(args ...interface{}) {
	tl.t.Helper()
	tl.handleLog(logMessage{lvl: DEBUG, args: args})
}
func (tl *testlogger) Debugf(format string, args ...interface{}) {
	tl.t.Helper()
	tl.handleLog(logMessage{lvl: DEBUG, msg: format, args: args})
}
func (tl *testlogger) Info(args ...interface{}) {
	tl.t.Helper()
	tl.handleLog(logMessage{lvl: INFO, args: args})
}

func (tl *testlogger) Infof(format string, args ...interface{}) {
	tl.t.Helper()
	tl.handleLog(logMessage{lvl: INFO, msg: format, args: args})
}

func (tl *testlogger) Warnf(format string, args ...interface{}) {
	tl.t.Helper()
	tl.handleLog(logMessage{lvl: WARN, msg: format, args: args})
}
func (tl *testlogger) Warnw(msg string, keysAndValues ...interface{}) {
	tl.t.Helper()
	tl.handleLog(logMessage{lvl: WARN, msg: msg, args: keysAndValues})
}
func (tl *testlogger) Error(args ...interface{}) {
	tl.t.Helper()
	tl.handleLog(logMessage{lvl: ERROR, args: args})
}
func (tl *testlogger) Errorf(format string, args ...interface{}) {
	tl.handleLog(logMessage{lvl: ERROR, msg: format, args: args})
}
func (tl *testlogger) Errorw(msg string, keysAndValues ...interface{}) {
	tl.t.Helper()
	tl.handleLog(logMessage{lvl: ERROR, msg: msg, args: keysAndValues})
}

func newTestLogger(t *testing.T) *testlogger {
	return &testlogger{
		t:    t,
		logs: []logMessage{},
	}
}
