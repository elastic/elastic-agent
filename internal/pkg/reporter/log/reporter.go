// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package log

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent-poc/internal/pkg/reporter"
)

type logger interface {
	Error(...interface{})
	Info(...interface{})
}

// Reporter is a reporter without any effects, serves just as a showcase for further implementations.
type Reporter struct {
	logger     logger
	formatFunc func(record reporter.Event) string
}

// NewReporter creates a new noop reporter
func NewReporter(l logger) *Reporter {
	return &Reporter{
		logger:     l,
		formatFunc: defaultFormatFunc,
	}
}

// Report in noop reporter does nothing
func (r *Reporter) Report(ctx context.Context, record reporter.Event) error {
	if record.Type() == reporter.EventTypeError {
		r.logger.Error(r.formatFunc(record))
		return nil
	}

	r.logger.Info(r.formatFunc(record))
	return nil
}

// Close stops all the background jobs reporter is running.
func (r *Reporter) Close() error { return nil }

func defaultFormatFunc(e reporter.Event) string {
	return fmt.Sprintf(defaultLogFormat,
		e.Time().Format(timeFormat),
		e.Message(),
		e.Type(),
		e.SubType(),
	)
}

// Check it is reporter.Backend
var _ reporter.Backend = &Reporter{}
