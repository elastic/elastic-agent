// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent/pkg/component"
)

type wrote struct {
	entry  zapcore.Entry
	fields []zapcore.Field
}

func TestLogWriter(t *testing.T) {
	scenarios := []struct {
		Name       string
		LogLevel   zapcore.Level
		UnitLevels map[string]zapcore.Level
		LogSource  logSource
		Config     component.CommandLogSpec
		Lines      []string
		Wrote      []wrote
	}{
		{
			Name:      "multi plain text line - info/stdout",
			LogLevel:  zapcore.InfoLevel,
			LogSource: logSourceStdout,
			Lines: []string{
				"simple written line\r\n",
				"another written line\n",
			},
			Wrote: []wrote{
				{
					entry: zapcore.Entry{
						Level:   zapcore.InfoLevel,
						Time:    time.Time{},
						Message: "simple written line",
					},
				},
				{
					entry: zapcore.Entry{
						Level:   zapcore.InfoLevel,
						Time:    time.Time{},
						Message: "another written line",
					},
				},
			},
		},
		{
			Name:      "multi plain text line - info/stderr",
			LogLevel:  zapcore.InfoLevel,
			LogSource: logSourceStderr,
			Lines: []string{
				"simple written line\r\n",
				"another written line\n",
			},
			Wrote: []wrote{
				{
					entry: zapcore.Entry{
						Level:   zapcore.ErrorLevel,
						Time:    time.Time{},
						Message: "simple written line",
					},
				},
				{
					entry: zapcore.Entry{
						Level:   zapcore.ErrorLevel,
						Time:    time.Time{},
						Message: "another written line",
					},
				},
			},
		},
		{
			Name:      "multi plain text line - error/stdout",
			LogLevel:  zapcore.ErrorLevel,
			LogSource: logSourceStdout,
			Lines: []string{
				"simple written line\r\n",
				"another written line\n",
			},
			Wrote: []wrote{},
		},
		{
			Name:      "multi split text line",
			LogLevel:  zapcore.InfoLevel,
			LogSource: logSourceStdout,
			Lines: []string{
				"simple written line\r\n",
				" another line sp",
				"lit on ",
				"",
				"multi writes\n",
				"\r\n",
				"\n",
			},
			Wrote: []wrote{
				{
					entry: zapcore.Entry{
						Level:   zapcore.InfoLevel,
						Time:    time.Time{},
						Message: "simple written line",
					},
				},
				{
					entry: zapcore.Entry{
						Level:   zapcore.InfoLevel,
						Time:    time.Time{},
						Message: "another line split on multi writes",
					},
				},
			},
		},
		{
			Name:      "json log line split",
			LogLevel:  zapcore.DebugLevel,
			LogSource: logSourceStdout,
			Config: component.CommandLogSpec{
				LevelKey:   "log.level",
				TimeKey:    "@timestamp",
				TimeFormat: time.RFC3339Nano,
				MessageKey: "message",
				IgnoreKeys: []string{"ignore"},
			},
			Lines: []string{
				`{"@timestamp": "2009-11-10T23:00:00Z", "log.level": "debug", "message": "message`,
				` field", "string": "extra", "int": 50, "ignore": "other"}`,
				"\n",
			},
			Wrote: []wrote{
				{
					entry: zapcore.Entry{
						Level:   zapcore.DebugLevel,
						Time:    parseTime("2009-11-10T23:00:00Z", time.RFC3339Nano),
						Message: "message field",
					},
					fields: []zapcore.Field{
						zap.String("string", "extra"),
						zap.Float64("int", 50),
					},
				},
			},
		},
		{
			Name:      "invalid JSON line",
			LogLevel:  zapcore.DebugLevel,
			LogSource: logSourceStdout,
			Lines: []string{
				`{"broken": json`,
				"\n",
			},
			Wrote: []wrote{
				{
					entry: zapcore.Entry{
						Level:   zapcore.InfoLevel,
						Time:    time.Time{},
						Message: `{"broken": json`,
					},
				},
			},
		},
		{
			Name:      "JSON drop log due to level",
			LogLevel:  zapcore.WarnLevel,
			LogSource: logSourceStdout,
			Lines: []string{
				`{"log.level": "info", "message": "not logged"}`,
				"\n",
			},
			Wrote: []wrote{},
		},
		{
			Name:      "JSON keep log due to level",
			LogLevel:  zapcore.InfoLevel,
			LogSource: logSourceStdout,
			Lines: []string{
				`{"@timestamp": "2009-11-10T23:00:00Z", "log.level": "info", "message": "message"}`,
				"\n",
			},
			Config: component.CommandLogSpec{
				LevelKey:   "log.level",
				TimeKey:    "@timestamp",
				TimeFormat: time.RFC3339Nano,
				MessageKey: "message",
			},
			Wrote: []wrote{
				{
					entry: zapcore.Entry{
						Level:   zapcore.InfoLevel,
						Time:    parseTime("2009-11-10T23:00:00Z", time.RFC3339Nano),
						Message: "message",
					},
					fields: []zapcore.Field{},
				},
			},
		},
		{
			Name:     "JSON drop unit specific log",
			LogLevel: zapcore.ErrorLevel,
			UnitLevels: map[string]zapcore.Level{
				"my-unit-id": zapcore.DebugLevel,
			},
			LogSource: logSourceStdout,
			Lines: []string{
				`{"@timestamp": "2009-11-10T23:00:00Z", "log.level": "info", "message": "info message", "unit.id": "my-unit-id"}`,
				"\n",
				`{"@timestamp": "2009-11-10T23:00:00Z", "log.level": "debug", "message": "debug message", "unit.id": "my-unit-id"}`,
				"\n",
				`{"@timestamp": "2009-11-10T23:00:00Z", "log.level": "info", "message": "info message", "unit": {"id": "my-unit-id"}}`,
				"\n",
				`{"@timestamp": "2009-11-10T23:00:00Z", "log.level": "info", "message": "dropped", "unit": {"id": "other-unit-id"}}`,
				"\n",
				`{"@timestamp": "2009-11-10T23:00:00Z", "log.level": "info", "message": "dropped"}`,
				"\n",
			},
			Config: component.CommandLogSpec{
				LevelKey:   "log.level",
				TimeKey:    "@timestamp",
				TimeFormat: time.RFC3339Nano,
				MessageKey: "message",
			},
			Wrote: []wrote{
				{
					entry: zapcore.Entry{
						Level:   zapcore.InfoLevel,
						Time:    parseTime("2009-11-10T23:00:00Z", time.RFC3339Nano),
						Message: "info message",
					},
					fields: []zapcore.Field{
						zap.String("unit.id", "my-unit-id"),
					},
				},
				{
					entry: zapcore.Entry{
						Level:   zapcore.DebugLevel,
						Time:    parseTime("2009-11-10T23:00:00Z", time.RFC3339Nano),
						Message: "debug message",
					},
					fields: []zapcore.Field{
						zap.String("unit.id", "my-unit-id"),
					},
				},
				{
					entry: zapcore.Entry{
						Level:   zapcore.InfoLevel,
						Time:    parseTime("2009-11-10T23:00:00Z", time.RFC3339Nano),
						Message: "info message",
					},
					fields: []zapcore.Field{
						zap.Any("unit", map[string]interface{}{
							"id": "my-unit-id",
						}),
					},
				},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			c := &captureCore{}
			w := newLogWriter(c, scenario.Config, scenario.LogLevel, scenario.UnitLevels, scenario.LogSource)
			for _, line := range scenario.Lines {
				l := len([]byte(line))
				c, err := w.Write([]byte(line))
				require.NoError(t, err)
				require.Equal(t, l, c)
			}
			require.Len(t, c.wrote, len(scenario.Wrote))
			for i := 0; i < len(scenario.Wrote); i++ {
				e := scenario.Wrote[i]
				o := c.wrote[i]
				if e.entry.Time.IsZero() {
					// can't ensure times match; set it to observed before ensuring its equal
					e.entry.Time = o.entry.Time
				}
				assert.Equal(t, e.entry, o.entry)

				// ensure the fields are in the same order (doesn't really matter for logging; but test cares)
				if len(e.fields) > 0 {
					sortFields(e.fields)
				}
				if len(o.fields) > 0 {
					sortFields(o.fields)
				}
				assert.EqualValues(t, e.fields, o.fields)
			}
		})
	}
}

type captureCore struct {
	wrote []wrote
}

func (c *captureCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	c.wrote = append(c.wrote, wrote{
		entry:  entry,
		fields: fields,
	})
	return nil
}

func parseTime(t string, format string) time.Time {
	v, err := time.Parse(format, t)
	if err != nil {
		panic(err)
	}
	return v
}

func sortFields(fields []zapcore.Field) {
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Key < fields[j].Key
	})
}
