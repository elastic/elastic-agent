// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent/pkg/component"
)

type zapcoreWriter interface {
	Write(zapcore.Entry, []zapcore.Field) error
}

// logWriter is an `io.Writer` that takes lines and passes them through the logger.
//
// `Write` handles parsing lines as either ndjson or plain text.
type logWriter struct {
	loggerCore zapcoreWriter
	logCfg     component.CommandLogSpec
	remainder  []byte
}

func newLogWriter(core zapcoreWriter, logCfg component.CommandLogSpec) *logWriter {
	return &logWriter{
		loggerCore: core,
		logCfg:     logCfg,
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
			r.remainder = append(r.remainder, p[offset:]...)
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
		if str[0:1] == "ty" {
			fmt.Println("found it")
		}
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
	lvl := getLevel(evt, r.logCfg.LevelKey)
	ts := getTimestamp(evt, r.logCfg.TimeKey, r.logCfg.TimeFormat)
	msg := getMessage(evt, r.logCfg.MessageKey)
	fields := getFields(evt, r.logCfg.IgnoreKeys)
	_ = r.loggerCore.Write(zapcore.Entry{
		Level:   lvl,
		Time:    ts,
		Message: msg,
	}, fields)
	return true
}

func getLevel(evt map[string]interface{}, key string) zapcore.Level {
	lvl := zapcore.InfoLevel
	err := unmarshalLevel(&lvl, getStrVal(evt, key))
	if err == nil {
		delete(evt, key)
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

func getMessage(evt map[string]interface{}, key string) string {
	msg := getStrVal(evt, key)
	if msg != "" {
		delete(evt, key)
	}
	return msg
}

func getTimestamp(evt map[string]interface{}, key string, format string) time.Time {
	t, err := time.Parse(format, getStrVal(evt, key))
	if err == nil {
		delete(evt, key)
		return t
	}
	return time.Now()
}

func getFields(evt map[string]interface{}, ignore []string) []zapcore.Field {
	fields := make([]zapcore.Field, 0, len(evt))
	for k, v := range evt {
		if len(ignore) > 0 && contains(ignore, k) {
			// ignore field
			continue
		}
		fields = append(fields, zap.Any(k, v))
	}
	return fields
}

func getStrVal(evt map[string]interface{}, key string) string {
	raw, ok := evt[key]
	if !ok {
		return ""
	}
	str, ok := raw.(string)
	if !ok {
		return ""
	}
	return str
}

func contains(s []string, val string) bool {
	for _, v := range s {
		if v == val {
			return true
		}
	}
	return false
}
