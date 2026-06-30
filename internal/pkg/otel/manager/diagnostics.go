// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"

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
		// These three errors mean EDOT is not running, which is expected.
		// fs.ErrNotExist: the socket file is missing (POSIX ENOENT / Windows ERROR_FILE_NOT_FOUND).
		// syscall.ECONNREFUSED: the socket file exists but nothing is listening (EDOT crashed or mid-restart).
		// context.DeadlineExceeded: a Windows pipe-busy dial timed out. This is defensive: production does not
		// set a dial deadline, so this only fires if the caller passes a deadline.
		// Any other error is unexpected, so surface it on each component so it ends up in the diagnostics archive.
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, context.DeadlineExceeded) {
			m.managerLogger.Debugf("EDOT not reachable, no diagnostics available: %v", err)
		} else {
			m.managerLogger.Warnf("failed to fetch diagnostics from EDOT: %v", err)
			for idx := range diagnostics {
				diagnostics[idx].Err = fmt.Errorf("error fetching otel diagnostics: %w", err)
			}
		}
		return diagnostics, nil
	}

	// Receiver names have the form "<receiverType>/_agent-component/<comp.ID>/<streamID>".
	// All "/" characters are literal string delimiters, not filesystem path separators,
	// so this is consistent across platforms including Windows.
	// We extract comp.ID as the segment between OtelNamePrefix and the next "/". This is
	// exact and unambiguous for normal IDs. Both comp.ID and streamID are user-supplied
	// (from the policy input "id" field), so either could contain "/" — making the format
	// ambiguous in that case. The warning below flags such IDs. A proper fix requires
	// escaping "/" in IDs at the source in the beat receiver.
	diagIdxByCompID := make(map[string]int)
	for idx, diag := range diagnostics {
		if strings.Contains(diag.Component.ID, "/") {
			m.managerLogger.Warnf("component ID %q contains '/', its EDOT diagnostics will be missing from the archive", diag.Component.ID)
		}
		diagIdxByCompID[diag.Component.ID] = idx
	}
	for _, extDiag := range extDiagnostics.ComponentDiagnostics {
		parts := strings.SplitN(extDiag.Name, translate.OtelNamePrefix, 2)
		if len(parts) != 2 {
			continue
		}
		compID, _, _ := strings.Cut(parts[1], "/")
		if idx, ok := diagIdxByCompID[compID]; ok {
			diagnostics[idx].Results = append(diagnostics[idx].Results, extDiag)
		}
	}

	return diagnostics, nil
}
