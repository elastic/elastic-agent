// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent/pkg/component"
)

type zapcoreWriter interface {
	Write(zapcore.Entry, []zapcore.Field) error
}

type logSource uint8

const (
	logSourceStdout logSource = 0
	logSourceStderr logSource = 1
)

// logWriter is an `io.Writer` that takes lines and passes them through the logger.
//
// `Write` handles parsing lines as either ndjson or plain text.
type logWriter struct {
	loggerCore zapcoreWriter
	logCfg     component.CommandLogSpec
	logLevel   zap.AtomicLevel

	mx         sync.Mutex
	unitLevels map[string]zapcore.Level
	remainder  []byte

	// inheritLevel is the level that will be used for a log message in the case it doesn't define a log level
	// for stdout it is INFO and for stderr it is ERROR.
	inheritLevel zapcore.Level
}

func newLogWriter(core zapcoreWriter, logCfg component.CommandLogSpec, ll zapcore.Level, unitLevels map[string]zapcore.Level, src logSource) *logWriter {
	inheritLevel := zapcore.InfoLevel
	if src == logSourceStderr {
		inheritLevel = zapcore.ErrorLevel
	}
	return &logWriter{
		loggerCore:   core,
		logCfg:       logCfg,
		logLevel:     zap.NewAtomicLevelAt(ll),
		unitLevels:   unitLevels,
		inheritLevel: inheritLevel,
	}
}

func NewLogWriterWithDefaults(core zapcoreWriter, ll zapcore.Level) *logWriter {
	cmdLogSpec := component.CommandLogSpec{}
	cmdLogSpec.InitDefaults()
	return &logWriter{
		loggerCore:   core,
		logCfg:       cmdLogSpec,
		logLevel:     zap.NewAtomicLevelAt(ll),
		inheritLevel: ll,
	}
}

func (r *logWriter) SetLevels(ll zapcore.Level, unitLevels map[string]zapcore.Level) {
	// must hold to lock so Write doesn't access the unitLevels
	r.mx.Lock()
	defer r.mx.Unlock()
	r.logLevel.SetLevel(ll)
	r.unitLevels = unitLevels
}

func (r *logWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		// nothing to do
		return 0, nil
	}

	// hold the lock so SetLevels and the remainder is not touched
	// from multiple go routines
	r.mx.Lock()
	defer r.mx.Unlock()

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
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			// empty line after trim
			continue
		}
		// try to parse line as JSON
		if trimmed[0] == '{' && r.handleJSON(trimmed) {
			// handled as JSON
			continue
		}
		// considered standard text being it's not JSON, log at inherit level (if enabled)
		if r.logLevel.Level().Enabled(r.inheritLevel) {
			_ = r.loggerCore.Write(zapcore.Entry{
				Level:   r.inheritLevel,
				Time:    time.Now(),
				Message: string(trimmed),
			}, nil)
		}
	}
}

func (r *logWriter) handleJSON(line []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return false
	}
	lvl := getLevel(raw, r.logCfg.LevelKey)
	ts := getTimestamp(raw, r.logCfg.TimeKey, r.logCfg.TimeFormat)
	msg := getMessage(raw, r.logCfg.MessageKey)

	allowedLvl := r.logLevel.Level()
	unitId := getUnitId(raw)
	if unitId != "" {
		if r.unitLevels != nil {
			if unitLevel, ok := r.unitLevels[unitId]; ok {
				allowedLvl = unitLevel
			}
		}
	}
	if allowedLvl.Enabled(lvl) {
		_ = r.loggerCore.Write(zapcore.Entry{
			Level:   lvl,
			Time:    ts,
			Message: msg,
		}, getFields(raw, r.logCfg.IgnoreKeys))
	}
	return true
}

func getLevel(raw map[string]json.RawMessage, key string) zapcore.Level {
	lvl := zapcore.InfoLevel
	if err := unmarshalLevel(&lvl, getStrVal(raw, key)); err == nil {
		delete(raw, key)
	}
	return lvl
}

func unmarshalLevel(lvl *zapcore.Level, val string) error {
	switch val {
	case "":
		return errors.New("empty val")
	case "trace":
		// zap doesn't handle trace level we cast to debug
		*lvl = zapcore.DebugLevel
		return nil
	default:
		return lvl.UnmarshalText([]byte(val))
	}
}

func getMessage(raw map[string]json.RawMessage, key string) string {
	msg := getStrVal(raw, key)
	if msg != "" {
		delete(raw, key)
	}
	return msg
}

func getTimestamp(raw map[string]json.RawMessage, key string, format string) time.Time {
	t, err := time.Parse(format, getStrVal(raw, key))
	if err == nil {
		delete(raw, key)
		return t
	}
	return time.Now()
}

func getFields(raw map[string]json.RawMessage, ignore []string) []zapcore.Field {
	fields := make([]zapcore.Field, 0, len(raw))
	for k, v := range raw {
		if len(ignore) > 0 && contains(ignore, k) {
			continue
		}
		var val interface{}
		if err := json.Unmarshal(v, &val); err != nil {
			fields = append(fields, zap.String(k, string(v)))
		} else {
			fields = append(fields, zap.Any(k, val))
		}
	}
	return fields
}

func getStrVal(raw map[string]json.RawMessage, key string) string {
	v, ok := raw[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return ""
	}
	return s
}

func contains(s []string, val string) bool {
	for _, v := range s {
		if v == val {
			return true
		}
	}
	return false
}

func getUnitId(raw map[string]json.RawMessage) string {
	if s := getStrVal(raw, "unit.id"); s != "" {
		return s
	}
	if v, ok := raw["unit"]; ok {
		var unitMap map[string]json.RawMessage
		if err := json.Unmarshal(v, &unitMap); err == nil {
			if s := getStrVal(unitMap, "id"); s != "" {
				return s
			}
		}
	}
	return ""
}
