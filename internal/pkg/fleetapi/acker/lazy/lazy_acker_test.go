// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package lazy

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var (
	errFoo = errors.New("error foo")
)

type testRetrier struct {
	enqueuedActions []fleetapi.Action
	expectedActions []fleetapi.Action
}

func (r *testRetrier) Enqueue(actions []fleetapi.Action) {
	r.enqueuedActions = actions
}

type testAcker struct {
	ackResponse *fleetapi.AckResponse
	errResponse error

	receivedActions []fleetapi.Action
	isCalled        bool
}

func (a *testAcker) AckBatch(ctx context.Context, actions []fleetapi.Action) (*fleetapi.AckResponse, error) {
	a.isCalled = true
	a.receivedActions = actions
	return a.ackResponse, a.errResponse
}

// Custom test comparer for actions slices
func actionsComparer(a, b []fleetapi.Action) bool {
	if len(a) != len(b) {
		return false
	}

	if (a == nil && b != nil) || (a != nil && b == nil) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if a[i].ID() != b[i].ID() {
			return false
		}
		if a[i].Type() != b[i].Type() {
			return false
		}
	}
	return true
}

func dedupeActions(actions []fleetapi.Action) []fleetapi.Action {
	set := make(map[string]struct{})

	var deduped []fleetapi.Action
	for _, action := range actions {
		if _, ok := set[action.ID()]; !ok {
			set[action.ID()] = struct{}{}
			deduped = append(deduped, action)
		}

	}
	return deduped
}

func TestLazyAcker(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	cfg := logger.DefaultLoggingConfig()
	cfg.Level = logp.DebugLevel
	// cfg.ToFiles = false
	cfg.ToStderr = true
	log, _ := logger.NewFromConfig("", cfg, true)

	// Tests
	tests := []struct {
		name        string
		actions     []fleetapi.Action
		expectedErr error

		acker   *testAcker
		retrier *testRetrier
	}{
		{
			name: "empty",
		},
		{
			name:    "no retrier",
			actions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "1"}},
		},
		{
			name:        "no retrier with error",
			actions:     []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "1"}},
			expectedErr: errFoo,
		},
		{
			name:    "with retrier, no error",
			actions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "1"}},
			acker:   &testAcker{ackResponse: &fleetapi.AckResponse{Items: []fleetapi.AckResponseItem{{Status: http.StatusOK}}}},
			retrier: &testRetrier{},
		},
		{
			name:    "with retrier, error",
			actions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "1"}},
			acker:   &testAcker{errResponse: errFoo},
			retrier: &testRetrier{expectedActions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "1"}}},
		},
		{
			name:    "with retrier, item not found",
			actions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "1"}},
			acker:   &testAcker{ackResponse: &fleetapi.AckResponse{Errors: true, Items: []fleetapi.AckResponseItem{{Status: http.StatusNotFound}}}},
			retrier: &testRetrier{expectedActions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "1"}}},
		},
		{
			name:    "with retrier, one item not found",
			actions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "1"}, &fleetapi.ActionUnknown{ActionID: "2"}, &fleetapi.ActionUnknown{ActionID: "3"}},
			acker: &testAcker{ackResponse: &fleetapi.AckResponse{Errors: true, Items: []fleetapi.AckResponseItem{
				{Status: http.StatusOK},
				{Status: http.StatusNotFound},
				{Status: http.StatusOK},
			}}},
			retrier: &testRetrier{expectedActions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "2"}}},
		},
		{
			name:    "with retrier, duplicated item with item not found",
			actions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "1"}, &fleetapi.ActionUnknown{ActionID: "1"}, &fleetapi.ActionUnknown{ActionID: "2"}, &fleetapi.ActionUnknown{ActionID: "3"}},
			acker: &testAcker{ackResponse: &fleetapi.AckResponse{Errors: true, Items: []fleetapi.AckResponseItem{
				{Status: http.StatusOK},
				{Status: http.StatusNotFound},
				{Status: http.StatusOK},
			}}},
			retrier: &testRetrier{expectedActions: []fleetapi.Action{&fleetapi.ActionUnknown{ActionID: "2"}}},
		},
	}

	// Iterate through tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var opts []Option
			if tc.retrier != nil {
				opts = append(opts, WithRetrier(tc.retrier))
			}
			batchAcker := tc.acker
			if batchAcker == nil {
				batchAcker = &testAcker{errResponse: tc.expectedErr}
			}
			acker := NewAcker(batchAcker, log, opts...)
			for _, action := range tc.actions {
				err := acker.Ack(ctx, action)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := acker.Commit(ctx)
			if err != nil {
				if !errors.Is(err, tc.expectedErr) {
					t.Fatalf("expected error: %v, got: %v", tc.expectedErr, err)
				}
			} else {
				if tc.expectedErr != nil {
					t.Fatalf("expected error: %v, got: %v", tc.expectedErr, err)
				}
			}

			// Check that AckBatch is called if actions are not empty
			diff := cmp.Diff(batchAcker.isCalled, len(tc.actions) > 0)
			if diff != "" {
				t.Fatal(diff)
			}

			// Compare AckBatch received actions
			diff = cmp.Diff(dedupeActions(tc.actions), batchAcker.receivedActions, cmp.Comparer(actionsComparer))
			if diff != "" {
				t.Fatal(diff)
			}

			// If retrier is not nil check the actions are retried
			if tc.retrier != nil {
				diff = cmp.Diff(tc.retrier.expectedActions, tc.retrier.enqueuedActions, cmp.Comparer(actionsComparer))
				if diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}
