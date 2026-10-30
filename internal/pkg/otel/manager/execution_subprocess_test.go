// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"

	runtimeLogger "github.com/elastic/elastic-agent/pkg/component/runtime"
)

// noopZapWriter discards entries; used to terminate the writer chain in tests.
type noopZapWriter struct{}

func (noopZapWriter) Write(zapcore.Entry, []zapcore.Field) error { return nil }

func TestLastMessage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		writes []string // each element simulates one line written to the subprocess output
		want   string
	}{
		{
			name:   "single line error",
			writes: []string{"something went wrong\n"},
			want:   "something went wrong",
		},
		{
			name: "multi-line config unmarshal error",
			writes: []string{
				// Reproduced with upstream otel/opentelemetry-collector-contrib
				// when the config references unknown component types. The cobra
				// command writes the error to stderr; the error contains embedded
				// newlines because the config unmarshaller joins per-component
				// errors. logWriter splits on \n, producing multiple zapcore
				// entries — all plain text (no fields), so zapLast accumulates
				// them into a single message.
				"Error: failed to get config: cannot unmarshal the configuration: decoding failed due to the following error(s):\n" +
					"\n" +
					"'receivers' unknown type: \"doesnotexist1\" for id: \"doesnotexist1\"\n" +
					"'exporters' unknown type: \"doesnotexist3\" for id: \"doesnotexist3\"\n",
			},
			want: `Error: failed to get config: cannot unmarshal the configuration: decoding failed due to the following error(s):; ` +
				`'receivers' unknown type: "doesnotexist1" for id: "doesnotexist1"; ` +
				`'exporters' unknown type: "doesnotexist3" for id: "doesnotexist3"`,
		},
		{
			name: "normal JSON logs followed by plain-text error",
			writes: []string{
				// Collector startup JSON log — logWriter parses it as JSON and
				// calls zapLast.Write with non-nil fields, resetting the batch.
				`{"level":"info","ts":"2025-01-01T00:00:00Z","msg":"Everything is ready. Begin running and processing data."}` + "\n",
				// Then the binary writes a plain-text error to stderr — no JSON
				// parsing, so fields are nil and the line accumulates.
				"config validation failed\n",
			},
			want: "config validation failed",
		},
		{
			name:   "empty",
			writes: nil,
			want:   "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zl := newZapLast(noopZapWriter{})
			w := runtimeLogger.NewLogWriterWithDefaults(zl, zapcore.InfoLevel)

			for _, data := range tc.writes {
				_, err := fmt.Fprint(w, data)
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.want, zl.LastMessage())
		})
	}
}
