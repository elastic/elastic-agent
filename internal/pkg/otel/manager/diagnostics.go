// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"

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
	if err != nil {
		// otel.IsCollectorUnavailable covers the socket being missing or refusing
		// connections, both of which mean the collector isn't running, which is
		// expected. context.DeadlineExceeded is additionally treated the same way
		// here for a Windows-specific case: a pipe-busy dial timing out. This is
		// defensive: production does not set a dial deadline, so this only fires
		// if the caller passes one.
		// Any other error is unexpected, so surface it on each component so it ends up in the diagnostics archive.
		if otel.IsCollectorUnavailable(err) || errors.Is(err, context.DeadlineExceeded) {
			m.managerLogger.Debugf("collector not reachable, no diagnostics available: %v", err)
		} else {
			m.managerLogger.Warnf("failed to fetch diagnostics from collector: %v", err)
			for idx := range diagnostics {
				diagnostics[idx].Err = fmt.Errorf("error fetching otel diagnostics: %w", err)
			}
		}
		return diagnostics, nil
	}

	diagIdxByCompID := make(map[string]int)
	for idx, diag := range diagnostics {
		diagIdxByCompID[diag.Component.ID] = idx
	}
	for _, extDiag := range extDiagnostics.ComponentDiagnostics {
		componentIDs := diagnosticComponentIDsFromName(extDiag.Name, currentComponents)
		if len(componentIDs) == 0 {
			m.managerLogger.Debugf("skipping EDOT diagnostic for %q: it cannot be associated with an active component", extDiag.Name)
			continue
		}
		if len(componentIDs) > 1 {
			m.managerLogger.Warnf("EDOT diagnostic %q is associated with multiple components %q; preserving it for each component", extDiag.Name, componentIDs)
		}
		for _, compID := range componentIDs {
			if idx, ok := diagIdxByCompID[compID]; ok {
				diagnostics[idx].Results = append(diagnostics[idx].Results, extDiag)
			}
		}
	}

	return diagnostics, nil
}

// diagnosticComponentIDsFromName matches the receiver type and treats component
// IDs as opaque candidates, without attempting to split out a stream ID. More
// than one same-type match is retained so diagnostics remain lossless when
// component and stream IDs make the flattened receiver name ambiguous.
func diagnosticComponentIDsFromName(name string, components []component.Component) []string {
	receiverType, suffix, found := strings.Cut(name, "/"+translate.OtelNamePrefix)
	if !found {
		return nil
	}

	componentIDs := make([]string, 0, 1)
	for _, comp := range components {
		beatName := comp.BeatName()
		if beatName == "" || receiverType != beatName+"receiver" {
			continue
		}
		if suffix == comp.ID || strings.HasPrefix(suffix, comp.ID+"/") {
			componentIDs = append(componentIDs, comp.ID)
		}
	}
	slices.Sort(componentIDs)
	return componentIDs
}
