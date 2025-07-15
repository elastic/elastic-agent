// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"testing"

	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/component"
)

func TestPerformComponentDiagnostics(t *testing.T) {
	logger, _ := loggertest.New("test")
	compID := "filebeat-comp-1"

	filebeatComp := testComponent(compID)
	filebeatComp.InputSpec.Spec.Command.Args = []string{"filebeat"}

	otherComp := testComponent("other-comp")
	otherComp.InputSpec.Spec.Command.Args = []string{"metricbeat"}

	m := &OTelManager{
		logger:     logger,
		components: []component.Component{filebeatComp, otherComp},
	}

	expectedDiags := []runtime.ComponentDiagnostic{
		{
			Component: filebeatComp,
		},
		{
			Component: otherComp,
		},
	}

	diags, err := m.PerformComponentDiagnostics(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, expectedDiags, diags)
}

func TestPerformDiagnostics(t *testing.T) {
	logger, _ := loggertest.New("test")
	compID := "filebeat-comp-1"

	filebeatComp := testComponent(compID)
	filebeatComp.InputSpec.Spec.Command.Args = []string{"filebeat"}

	otherComp := testComponent("other-comp")
	otherComp.InputSpec.Spec.Command.Args = []string{"metricbeat"}

	m := &OTelManager{
		logger:     logger,
		components: []component.Component{filebeatComp, otherComp},
	}

	t.Run("diagnose all units when no request is provided", func(t *testing.T) {
		expectedDiags := []runtime.ComponentUnitDiagnostic{
			{
				Component: filebeatComp,
				Unit:      filebeatComp.Units[0],
			},
			{
				Component: filebeatComp,
				Unit:      filebeatComp.Units[1],
			},
			{
				Component: otherComp,
				Unit:      otherComp.Units[0],
			},
			{
				Component: otherComp,
				Unit:      otherComp.Units[1],
			},
		}
		diags := m.PerformDiagnostics(t.Context())
		assert.Equal(t, expectedDiags, diags)
	})

	t.Run("diagnose specific unit", func(t *testing.T) {
		req := runtime.ComponentUnitDiagnosticRequest{
			Component: filebeatComp,
			Unit:      filebeatComp.Units[0],
		}
		expectedDiags := []runtime.ComponentUnitDiagnostic{
			{
				Component: filebeatComp,
				Unit:      filebeatComp.Units[0],
			},
		}
		diags := m.PerformDiagnostics(t.Context(), req)
		assert.Equal(t, expectedDiags, diags)
	})
}
