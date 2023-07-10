// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
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
	unitLevels map[string]zapcore.Level
	levelMx    sync.RWMutex
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

func (r *logWriter) SetLevels(ll zapcore.Level, unitLevels map[string]zapcore.Level) {
	r.logLevel.SetLevel(ll)
	r.levelMx.Lock()
	defer r.levelMx.Unlock()
	r.unitLevels = unitLevels
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
		// try to parse line as JSON
		if str[0] == '{' && r.handleJSON(str) {
			// handled as JSON
			continue
		}
		// considered standard text being it's not JSON, log at inherit level (if enabled)
		if r.logLevel.Level().Enabled(r.inheritLevel) {
			_ = r.loggerCore.Write(zapcore.Entry{
				Level:   r.inheritLevel,
				Time:    time.Now(),
				Message: str,
			}, nil)
		}
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

	allowedLvl := r.logLevel.Level()
	unitId := getUnitId(evt)
	if unitId != "" {
		r.levelMx.RLock()
		if r.unitLevels != nil {
			if unitLevel, ok := r.unitLevels[unitId]; ok {
				allowedLvl = unitLevel
			}
		}
		r.levelMx.RUnlock()
	}
	if allowedLvl.Enabled(lvl) {
		_ = r.loggerCore.Write(zapcore.Entry{
			Level:   lvl,
			Time:    ts,
			Message: msg,
		}, fields)
	}
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

func getUnitId(evt map[string]interface{}) string {
	if unitIdRaw, ok := evt["unit.id"]; ok {
		if unitId, ok := unitIdRaw.(string); ok && unitId != "" {
			return unitId
		}
	}
	if unitMapRaw, ok := evt["unit"]; ok {
		if unitMap, ok := unitMapRaw.(map[string]interface{}); ok {
			if unitIdRaw, ok := unitMap["id"]; ok {
				if unitId, ok := unitIdRaw.(string); ok && unitId != "" {
					return unitId
				}
			}
		}
	}
	return ""
}
