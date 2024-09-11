// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package retrier

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
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

	log, _ := logger.New("", false)

	tests := []struct {
		name             string
		actions          []fleetapi.Action
		acker            *testAcker
		expectedAckCalls int
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
		})
	}
}
