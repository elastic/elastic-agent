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
)

type wrote struct {
	entry  zapcore.Entry
	fields []zapcore.Field
}

func TestLogWriter(t *testing.T) {
	scenarios := []struct {
		Name  string
		Lines []string
		Wrote []wrote
	}{
		{
			Name: "multi plain text line",
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
			Name: "multi split text line",
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
			Name: "json log lines",
			Lines: []string{
				`{"@timestamp": "2009-11-10T23:00:00Z", "log.level": "debug", "message": "message field", "string": "extra", "int": 50}`,
				"\n",
				`{"timestamp": "2009-11-10T23:00:01Z", "log": {"level": "warn"}, "msg": "msg field", "string": "extra next", "int": 100}`,
				"\n",
				`{"time": "2009-11-10T23:00:02Z", "level": "trace", "message": "message field", "nested": {"key": "value"}}`,
				"\n",
				`{"level": "error", "message": "error string"}`,
				"\n",
			},
			Wrote: []wrote{
				{
					entry: zapcore.Entry{
						Level:   zapcore.DebugLevel,
						Time:    parseTime("2009-11-10T23:00:00Z"),
						Message: "message field",
					},
					fields: []zapcore.Field{
						zap.String("string", "extra"),
						zap.Float64("int", 50),
					},
				},
				{
					entry: zapcore.Entry{
						Level:   zapcore.WarnLevel,
						Time:    parseTime("2009-11-10T23:00:01Z"),
						Message: "msg field",
					},
					fields: []zapcore.Field{
						zap.String("string", "extra next"),
						zap.Float64("int", 100),
						zap.Any("log", map[string]interface{}{}),
					},
				},
				{
					entry: zapcore.Entry{
						Level:   zapcore.DebugLevel,
						Time:    parseTime("2009-11-10T23:00:02Z"),
						Message: "message field",
					},
					fields: []zapcore.Field{
						zap.Any("nested", map[string]interface{}{
							"key": "value",
						}),
					},
				},
				{
					entry: zapcore.Entry{
						Level:   zapcore.ErrorLevel,
						Time:    time.Time{},
						Message: "error string",
					},
					fields: []zapcore.Field{},
				},
			},
		},
		{
			Name: "invalid JSON line",
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
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			c := &captureCore{}
			w := newLogWriter(c)
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

func parseTime(t string) time.Time {
	v, err := time.Parse(time.RFC3339Nano, t)
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
