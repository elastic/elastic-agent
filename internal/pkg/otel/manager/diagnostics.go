// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/elastic/elastic-agent/internal/pkg/otel"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
)

// PerformDiagnostics executes the diagnostic action for the provided units. If no units are provided then
// it performs diagnostics for all current units. If a given unit does not exist in the manager, then a warning
// is logged.
func (m *OTelManager) PerformDiagnostics(ctx context.Context, req ...runtime.ComponentUnitDiagnosticRequest) []runtime.ComponentUnitDiagnostic {
	var diagnostics []runtime.ComponentUnitDiagnostic
	m.mx.RLock()
	currentComponents := m.components
	m.mx.RUnlock()

	// if no request is provided, then perform diagnostics for all units
	if len(req) == 0 {
		for _, comp := range currentComponents {
			for _, unit := range comp.Units {
				diagnostics = append(diagnostics, runtime.ComponentUnitDiagnostic{
					Component: comp,
					Unit:      unit,
				})
			}
		}
		return diagnostics
	}

	// create a map of unit by component and unit id, this is used to filter out units that
	// do not exist in the manager
	unitByID := make(map[string]map[string]*component.Unit)
	for _, r := range req {
		if unitByID[r.Component.ID] == nil {
			unitByID[r.Component.ID] = make(map[string]*component.Unit)
		}
		unitByID[r.Component.ID][r.Unit.ID] = &r.Unit
	}

	// create empty diagnostics for units that exist in the manager
	for _, existingComp := range currentComponents {
		inputComp, ok := unitByID[existingComp.ID]
		if !ok {
			m.managerLogger.Warnf("requested diagnostics for component %s, but it does not exist in the manager", existingComp.ID)
			continue
		}
		for _, unit := range existingComp.Units {
			if _, ok := inputComp[unit.ID]; ok {
				diagnostics = append(diagnostics, runtime.ComponentUnitDiagnostic{
					Component: existingComp,
					Unit:      unit,
				})
			} else {
				m.managerLogger.Warnf("requested diagnostics for unit %s, but it does not exist in the manager", unit.ID)
			}
		}
	}

	return diagnostics
}

// PerformComponentDiagnostics executes the diagnostic action for the provided components. If no components are provided,
// then it performs the diagnostics for all current components.
func (m *OTelManager) PerformComponentDiagnostics(
	ctx context.Context, additionalMetrics []cproto.AdditionalDiagnosticRequest, req ...component.Component,
) ([]runtime.ComponentDiagnostic, error) {
	var diagnostics []runtime.ComponentDiagnostic
	m.mx.RLock()
	currentComponents := m.components
	m.mx.RUnlock()

	// if no request is provided, then perform diagnostics for all components
	if len(req) == 0 {
		req = currentComponents
	}

	// create a map of component by id, this is used to filter out components that do not exist in the manager
	compByID := make(map[string]component.Component)
	for _, comp := range req {
		compByID[comp.ID] = comp
	}

	// create empty diagnostics for components that exist in the manager
	for _, existingComp := range currentComponents {
		if inputComp, ok := compByID[existingComp.ID]; ok {
			diagnostics = append(diagnostics, runtime.ComponentDiagnostic{
				Component: inputComp,
			})
		} else {
			m.managerLogger.Warnf("requested diagnostics for component %s, but it does not exist in the manager", existingComp.ID)
		}
	}

	extDiagnostics, err := otel.PerformDiagnosticsExt(ctx, false)

	// We're not running the EDOT if:
	//  1. Either the socket doesn't exist
	//	2. It is refusing the connections.
	// Return error for any other scenario.
	if err != nil {
		m.managerLogger.Debugf("Couldn't fetch diagnostics from EDOT: %v", err)
		if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("error fetching otel diagnostics: %w", err)
		}
	}

	for idx, diag := range diagnostics {
		found := false
		for _, extDiag := range extDiagnostics.ComponentDiagnostics {
			if strings.Contains(extDiag.Name, diag.Component.ID) {
				found = true
				diagnostics[idx].Results = append(diagnostics[idx].Results, extDiag)
			}
		}
		if !found {
			diagnostics[idx].Err = fmt.Errorf("failed to get diagnostics for %s", diag.Component.ID)
		}
	}

	return diagnostics, nil
}
