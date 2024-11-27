// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otelhelpers

import (
	"testing"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/component/componentstatus"
)

func TestHasStatus(t *testing.T) {
	scenarios := []struct {
		Name   string
		Result bool
		Has    componentstatus.Status
		Status *status.AggregateStatus
	}{
		{
			Name:   "empty",
			Result: false,
			Has:    componentstatus.StatusOK,
			Status: nil,
		},
		{
			Name:   "has status",
			Result: true,
			Has:    componentstatus.StatusOK,
			Status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
			},
		},
		{
			Name:   "doesn't have status",
			Result: false,
			Has:    componentstatus.StatusRecoverableError,
			Status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
			},
		},
		{
			Name:   "sub-component has status",
			Result: true,
			Has:    componentstatus.StatusRecoverableError,
			Status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"test-component": &status.AggregateStatus{
						Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
					},
				},
			},
		},
		{
			Name:   "sub-component doesn't have status",
			Result: false,
			Has:    componentstatus.StatusPermanentError,
			Status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"test-component": &status.AggregateStatus{
						Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
					},
				},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			observed := HasStatus(scenario.Status, scenario.Has)
			assert.Equal(t, scenario.Result, observed)
		})
	}
}
