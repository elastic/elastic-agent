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

	diags, err := m.PerformComponentDiagnostics(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, diags, 2)

	for _, d := range diags {
		assert.NotNil(t, d)
		assert.NotNil(t, d.Component)
		assert.Len(t, d.Results, 0)
	}
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
		diags := m.PerformDiagnostics(t.Context())
		require.Len(t, diags, 4) // two components, two units per component
		assert.Equal(t, "filestream-unit", diags[0].Unit.ID)
		assert.Equal(t, "filestream-default", diags[1].Unit.ID)
		assert.Len(t, diags[0].Results, 0)
	})

	t.Run("diagnose specific unit", func(t *testing.T) {
		req := runtime.ComponentUnitDiagnosticRequest{
			Component: filebeatComp,
			Unit:      filebeatComp.Units[0],
		}
		diags := m.PerformDiagnostics(t.Context(), req)
		require.Len(t, diags, 1)
		assert.Equal(t, "filestream-unit", diags[0].Unit.ID)
		assert.Len(t, diags[0].Results, 0)
	})
}
