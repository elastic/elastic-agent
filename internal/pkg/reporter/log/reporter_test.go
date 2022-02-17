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
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/reporter"
)

type testCase struct {
	event         reporter.Event
	expectedInfo  string
	expectedError string
}

func TestReport(t *testing.T) {
	infoEvent := generateEvent(reporter.EventTypeState, reporter.EventSubTypeStarting)
	errorEvent := generateEvent(reporter.EventTypeError, reporter.EventSubTypeConfig)

	testCases := []testCase{
		{infoEvent, DefaultString(infoEvent), ""},
		{errorEvent, "", DefaultString(errorEvent)},
	}

	for _, tc := range testCases {
		log := newTestLogger()
		rep := NewReporter(log)

		rep.Report(context.Background(), tc.event)

		if got := log.info(); tc.expectedInfo != got {
			t.Errorf("[%s(%v)] expected info '%s' got '%s'", tc.event.Type(), tc.event.SubType(), tc.expectedInfo, got)
		}

		if got := log.error(); tc.expectedError != got {
			t.Errorf("[%s(%v)] expected error '%s' got '%s'", tc.event.Type(), tc.event.SubType(), tc.expectedError, got)
		}
	}
}

type testLogger struct {
	errorLog string
	infoLog  string
}

func newTestLogger() *testLogger {
	t := &testLogger{}
	return t
}

func (t *testLogger) Error(args ...interface{}) {
	t.errorLog = fmt.Sprint(args...)
}

func (t *testLogger) Info(args ...interface{}) {
	t.infoLog = fmt.Sprint(args...)
}

func (t *testLogger) error() string {
	return t.errorLog
}

func (t *testLogger) info() string {
	return t.infoLog
}

func generateEvent(eventype, subType string) testEvent {
	return testEvent{
		eventtype: eventype,
		subType:   subType,
		timestamp: time.Unix(0, 1),
		message:   "message",
	}
}

type testEvent struct {
	eventtype string
	subType   string
	timestamp time.Time
	message   string
}

func (t testEvent) Type() string                  { return t.eventtype }
func (t testEvent) SubType() string               { return t.subType }
func (t testEvent) Time() time.Time               { return t.timestamp }
func (t testEvent) Message() string               { return t.message }
func (testEvent) Payload() map[string]interface{} { return map[string]interface{}{} }

func DefaultString(event testEvent) string {
	timestamp := event.timestamp.Format(timeFormat)
	return fmt.Sprintf("%s - message: message - type: '%s' - sub_type: '%s'", timestamp, event.Type(), event.SubType())
}
