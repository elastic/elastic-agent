// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"go.uber.org/zap"

	"go.uber.org/zap/zapcore"
)

type zapcoreWriter interface {
	Write(zapcore.Entry, []zapcore.Field) error
}

// logWriter is an `io.Writer` that takes lines and passes them through the logger.
//
// `Write` handles parsing lines as either ndjson or plain text.
type logWriter struct {
	loggerCore zapcoreWriter
	remainder  []byte
}

func newLogWriter(core zapcoreWriter) *logWriter {
	return &logWriter{
		loggerCore: core,
	}
}

func (r *logWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		// nothing to do
		return 0, nil
	}
	offset := 0
	for {
		idx := bytes.IndexByte(p[offset:], '\n')
		if idx < 0 {
			// not all used add to remainder to be used on next call
			if r.remainder == nil || len(r.remainder) == 0 {
				r.remainder = p[offset:]
			} else {
				r.remainder = append(r.remainder, p[offset:]...)
			}
			return len(p), nil
		}

		var line []byte
		if r.remainder != nil {
			line = r.remainder
			r.remainder = nil
			line = append(line, p[offset:offset+idx]...)
		} else {
			line = append(line, p[offset:offset+idx]...)
		}
		offset += idx + 1
		// drop '\r' from line (needed for Windows)
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[0 : len(line)-1]
		}
		if len(line) == 0 {
			// empty line
			continue
		}
		str := strings.TrimSpace(string(line))
		// try to parse line as JSON
		if str[0] == '{' && r.handleJSON(str) {
			// handled as JSON
			continue
		}
		// considered standard text being it's not JSON, log at basic info level
		_ = r.loggerCore.Write(zapcore.Entry{
			Level:   zapcore.InfoLevel,
			Time:    time.Now(),
			Message: str,
		}, nil)
	}
}

func (r *logWriter) handleJSON(line string) bool {
	var evt map[string]interface{}
	if err := json.Unmarshal([]byte(line), &evt); err != nil {
		return false
	}
	lvl := getLevel(evt)
	ts := getTimestamp(evt)
	msg := getMessage(evt)
	fields := getFields(evt)
	_ = r.loggerCore.Write(zapcore.Entry{
		Level:   lvl,
		Time:    ts,
		Message: msg,
	}, fields)
	return true
}

func getLevel(evt map[string]interface{}) zapcore.Level {
	lvl := zapcore.InfoLevel
	err := unmarshalLevel(&lvl, getStrVal(evt, "log.level"))
	if err != nil {
		err := unmarshalLevel(&lvl, getStrVal(evt, "log", "level"))
		if err != nil {
			err := unmarshalLevel(&lvl, getStrVal(evt, "level"))
			if err == nil {
				deleteVal(evt, "level")
			}
		} else {
			deleteVal(evt, "log", "level")
		}
	} else {
		deleteVal(evt, "log.level")
	}
	return lvl
}

func unmarshalLevel(lvl *zapcore.Level, val string) error {
	if val == "" {
		return errors.New("empty val")
	} else if val == "trace" {
		// zap doesn't handle trace level we cast to debug
		*lvl = zapcore.DebugLevel
		return nil
	}
	return lvl.UnmarshalText([]byte(val))
}

func getMessage(evt map[string]interface{}) string {
	msg := getStrVal(evt, "message")
	if msg == "" {
		msg = getStrVal(evt, "msg")
		if msg != "" {
			deleteVal(evt, "msg")
		}
	} else {
		deleteVal(evt, "message")
	}
	return msg
}

func getTimestamp(evt map[string]interface{}) time.Time {
	t, err := time.Parse(time.RFC3339Nano, getStrVal(evt, "@timestamp"))
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, getStrVal(evt, "timestamp"))
		if err != nil {
			t, err = time.Parse(time.RFC3339Nano, getStrVal(evt, "time"))
			if err != nil {
				t = time.Now()
			} else {
				deleteVal(evt, "time")
			}
		} else {
			deleteVal(evt, "timestamp")
		}
	} else {
		deleteVal(evt, "@timestamp")
	}
	return t
}

func getFields(evt map[string]interface{}) []zapcore.Field {
	fields := make([]zapcore.Field, 0, len(evt))
	for k, v := range evt {
		fields = append(fields, zap.Any(k, v))
	}
	return fields
}

func getStrVal(evt map[string]interface{}, fields ...string) string {
	if len(fields) == 0 {
		panic("must provide at least one field")
	}
	last := len(fields) - 1
	for i, field := range fields {
		if i == last {
			raw, ok := evt[field]
			if !ok {
				return ""
			}
			str, ok := raw.(string)
			if !ok {
				return ""
			}
			return str
		}
		raw, ok := evt[field]
		if !ok {
			return ""
		}
		nested, ok := raw.(map[string]interface{})
		if !ok {
			return ""
		}
		evt = nested
	}
	return ""
}

func deleteVal(evt map[string]interface{}, fields ...string) {
	if len(fields) == 0 {
		panic("must provide at least one field")
	}
	last := len(fields) - 1
	for i, field := range fields {
		if i == last {
			delete(evt, field)
			return
		}
		raw, ok := evt[field]
		if !ok {
			return
		}
		nested, ok := raw.(map[string]interface{})
		if !ok {
			return
		}
		evt = nested
	}
}
