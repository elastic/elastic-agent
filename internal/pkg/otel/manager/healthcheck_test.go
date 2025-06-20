// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"errors"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"
)

func TestCompareAggregateStatuses(t *testing.T) {
	timestamp := time.Now()
	for _, tc := range []struct {
		name     string
		s1, s2   *status.AggregateStatus
		expected bool
	}{
		{
			name: "equal statuses",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
			},
			expected: true,
		},
		{
			name: "unequal statuses",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusPermanentError,
					timestamp: timestamp,
					err:       nil,
				},
			},
			expected: false,
		},
		{
			name: "unequal errors",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       errors.New("error"),
				},
			},
			expected: false,
		},
		{
			name: "unequal component statuses",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:    componentstatus.StatusOK,
							timestamp: timestamp,
							err:       nil,
						},
					},
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:    componentstatus.StatusStopped,
							timestamp: timestamp,
							err:       nil,
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "more components",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:    componentstatus.StatusOK,
							timestamp: timestamp,
							err:       nil,
						},
					},
					"component2": {
						Event: &healthCheckEvent{
							status:    componentstatus.StatusOK,
							timestamp: timestamp,
							err:       nil,
						},
					},
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:    componentstatus.StatusOK,
							timestamp: timestamp,
							err:       nil,
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "completely different components",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:    componentstatus.StatusOK,
							timestamp: timestamp,
							err:       nil,
						},
					},
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component3": {
						Event: &healthCheckEvent{
							status:    componentstatus.StatusOK,
							timestamp: timestamp,
							err:       nil,
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "unequal component errors",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:    componentstatus.StatusOK,
							timestamp: timestamp,
							err:       errors.New("error1"),
						},
					},
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:    componentstatus.StatusOK,
							timestamp: timestamp,
							err:       errors.New("error2"),
						},
					},
				},
			},
			expected: false,
		},
		{
			name:     "both nil",
			s1:       nil,
			s2:       nil,
			expected: true,
		},
		{
			name: "one nil",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:    componentstatus.StatusOK,
					timestamp: timestamp,
					err:       nil,
				},
			},
			s2:       nil,
			expected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := compareStatuses(tc.s1, tc.s2)
			if actual != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, actual)
			}
		})
	}
}
