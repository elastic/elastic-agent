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

	// levelScanKey is `"<LevelKey>"` pre-built for scanLevel.
	levelScanKey []byte
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
		levelScanKey: buildLevelScanKey(logCfg.LevelKey),
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
		levelScanKey: buildLevelScanKey(cmdLogSpec.LevelKey),
	}
}

// buildLevelScanKey returns the JSON-quoted form of key, e.g. `"log.level"`.
func buildLevelScanKey(key string) []byte {
	b := make([]byte, len(key)+2)
	b[0] = '"'
	copy(b[1:], key)
	b[len(key)+1] = '"'
	return b
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
	allowedLvl := r.logLevel.Level()

	// When no per-unit levels are configured, use a cheap byte scan to skip
	// json.Unmarshal entirely for messages that fall below the log level.
	if r.unitLevels == nil {
		if lvl := scanLevel(line, r.levelScanKey); !allowedLvl.Enabled(lvl) {
			return true
		}
	}

	// Full parse: needed either to emit the log or to resolve per-unit levels.
	var evt map[string]interface{}
	if err := json.Unmarshal(line, &evt); err != nil {
		return false
	}

	lvl := getLevel(evt, r.logCfg.LevelKey)
	unitId := getUnitId(evt)
	if unitId != "" && r.unitLevels != nil {
		if unitLevel, ok := r.unitLevels[unitId]; ok {
			allowedLvl = unitLevel
		}
	}

	if allowedLvl.Enabled(lvl) {
		ts := getTimestamp(evt, r.logCfg.TimeKey, r.logCfg.TimeFormat)
		msg := getMessage(evt, r.logCfg.MessageKey)
		_ = r.loggerCore.Write(zapcore.Entry{
			Level:   lvl,
			Time:    ts,
			Message: msg,
		}, getFields(evt, r.logCfg.IgnoreKeys))
	}
	return true
}

// scanLevel does a cheap byte scan for key and returns the corresponding
// zapcore.Level without a full json.Unmarshal.
func scanLevel(line, key []byte) zapcore.Level {
	idx := bytes.Index(line, key)
	if idx < 0 {
		return zapcore.InfoLevel
	}
	i := idx + len(key)
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i >= len(line) || line[i] != ':' {
		return zapcore.InfoLevel
	}
	i++ // skip ':'
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i >= len(line) || line[i] != '"' {
		return zapcore.InfoLevel
	}
	i++ // skip opening '"'
	end := bytes.IndexByte(line[i:], '"')
	if end < 0 {
		return zapcore.InfoLevel
	}
	lvl := zapcore.InfoLevel
	_ = unmarshalLevel(&lvl, string(line[i:i+end]))
	return lvl
}

func getLevel(evt map[string]interface{}, key string) zapcore.Level {
	lvl := zapcore.InfoLevel
	v, ok := evt[key]
	if !ok {
		return lvl
	}
	s, ok := v.(string)
	if !ok {
		return lvl
	}
	if err := unmarshalLevel(&lvl, s); err == nil {
		delete(evt, key)
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

func getMessage(evt map[string]interface{}, key string) string {
	v, ok := evt[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	delete(evt, key)
	return s
}

func getTimestamp(evt map[string]interface{}, key, format string) time.Time {
	v, ok := evt[key]
	if !ok {
		return time.Now()
	}
	s, ok := v.(string)
	if !ok {
		return time.Now()
	}
	t, err := time.Parse(format, s)
	if err != nil {
		return time.Now()
	}
	delete(evt, key)
	return t
}

func getFields(evt map[string]interface{}, ignore []string) []zapcore.Field {
	fields := make([]zapcore.Field, 0, len(evt))
	for k, v := range evt {
		if len(ignore) > 0 && contains(ignore, k) {
			continue
		}
		fields = append(fields, zap.Any(k, v))
	}
	return fields
}

func contains(s []string, val string) bool {
	for _, v := range s {
		if v == val {
			return true
		}
	}
	return false
}

func getUnitId(evt map[string]interface{}) string {
	if v, ok := evt["unit.id"]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	if v, ok := evt["unit"]; ok {
		if m, ok := v.(map[string]interface{}); ok {
			if id, ok := m["id"]; ok {
				if s, ok := id.(string); ok {
					return s
				}
			}
		}
	}
	return ""
}
