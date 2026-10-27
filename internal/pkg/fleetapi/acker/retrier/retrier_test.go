// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package retrier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
)

var (
	errBar = errors.New("error bar")
)

type testAcker struct {
	errResponse error

	receivedActions []fleetapi.Action
	called          int

	// list of responses to replay depending on the attempt number
	responses []*fleetapi.AckResponse
}

func (a *testAcker) AckBatch(ctx context.Context, actions []fleetapi.Action) (*fleetapi.AckResponse, error) {
	defer func() {
		a.called++
	}()
	a.receivedActions = append(a.receivedActions, actions...)
	if len(a.responses) > 0 && a.called < len(a.responses) {
		return a.responses[a.called], nil
	}
	return nil, a.errResponse
}

func TestRetrier(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	tests := []struct {
		name             string
		actions          []fleetapi.Action
		acker            *testAcker
		expectedAckCalls int
		expectedDropped  []string
	}{
		{
			name:    "no error",
			actions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "1"}},
			acker: &testAcker{
				responses: []*fleetapi.AckResponse{
					{
						Items: []fleetapi.AckResponseItem{
							{Status: http.StatusOK},
						},
					},
				},
			},
			expectedAckCalls: 1,
		},
		{
			name:             "permanent error",
			actions:          []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "1"}},
			acker:            &testAcker{errResponse: errBar},
			expectedAckCalls: 3,
			expectedDropped:  []string{"1"},
		},
		{
			name: "partial error",
			actions: []fleetapi.Action{
				&fleetapi.ActionUnknown{ActionID: "1"},
				&fleetapi.ActionUnknown{ActionID: "2"},
				&fleetapi.ActionUnknown{ActionID: "3"},
			},
			acker: &testAcker{
				responses: []*fleetapi.AckResponse{
					{
						Errors: true,
						Items: []fleetapi.AckResponseItem{
							{Status: http.StatusOK},
							{Status: http.StatusNotFound},
							{Status: http.StatusOK},
						},
					},
					{
						Items: []fleetapi.AckResponseItem{
							{Status: http.StatusOK},
						},
					},
				},
			},
			expectedAckCalls: 2,
		},
	}

	const maxRetries = 3
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cn := context.WithCancel(ctx)
			defer cn()

			log, obsLogs := loggertest.New(tc.name)

			acker := tc.acker
			if acker == nil {
				acker = &testAcker{}
			}

			retrier := New(acker, log,
				WithInitialRetryInterval(50*time.Millisecond),
				WithMaxRetryInterval(time.Minute),
				WithMaxAckRetries(maxRetries),
			)

			cctx, ccn := context.WithCancel(ctx)
			go retrier.Run(cctx)

			retrier.Enqueue(tc.actions)

			// Wait until done
			<-retrier.Done()
			ccn()

			// Validate test
			diff := cmp.Diff(tc.expectedAckCalls, acker.called)
			if diff != "" {
				t.Fatal(diff)
			}

			dropLogs := obsLogs.
				FilterMessageSnippet("ack retrier: dropping ack").
				FilterLevelExact(zapcore.WarnLevel).
				All()
			require.Len(t, dropLogs, len(tc.expectedDropped))
			for i, id := range tc.expectedDropped {
				assert.Contains(t, dropLogs[i].Message, fmt.Sprintf("action id %q", id))
			}
		})
	}
}
