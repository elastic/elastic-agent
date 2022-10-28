// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"bytes"
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/control/client"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type Uploader interface {
	UploadDiagnostics(context.Context, string, *bytes.Buffer) error
}

type Diagnostics struct {
	log      *logger.Logger
	coord    *coordinator.Coordinator // TODO use of coordinator or control server/client?
	uploader Uploader
}

func NewDiagnostics(log *logger.Logger, coord *coordinator.Coordinator, uploader Uploader) *Diagnostics {
	return &Diagnostics{
		log:      log,
		coord:    coord,
		uploader: uploader,
	}
}

func (h *Diagnostics) Handle(ctx context.Context, a fleetapi.Action, ack acker.Acker) error {
	h.log.Debugf("handlerDiagnostics: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionDiagnostics)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionDiagnostics and received %T", a)
	}

	// Gather agent diagnostics
	diagHooks := append(diagnostics.GlobalHooks(), h.coord.DiagnosticHooks()()...)
	aDiag := make([]client.DiagnosticFileResult, 0, len(diagHooks))
	for _, hook := range diagHooks {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		p, ts := hook.Hook(ctx)
		aDiag = append(aDiag, client.DiagnosticFileResult{
			Name:        hook.Name,
			Filename:    hook.Filename,
			Description: hook.Description,
			ContentType: hook.ContentType,
			Content:     p,
			Generated:   ts,
		})
	}

	// Gather unit diagnostics
	units := make([]component.Unit, 0, len(action.Units))
	for _, u := range action.Units {
		units = append(units, component.Unit{
			ID:   u.ID,
			Type: client.UnitType(u.UnitType),
		})
	}
	runtimeDiag := h.coord.PerformDiagnostics(ctx, units...)
	uDiag := make([]client.DiagnosticUnitResult, 0, len(runtimeDiag))
	for _, diag := range runtimeDiag {
		files := make([]client.DiagnosticFileResult, 0, diag.Results)
		for _, f := range diag.Results {
			files = append(files, client.DiagnosticFileResult{
				Name:        f.Name,
				Filename:    f.Filename,
				Description: f.Description,
				ContentType: f.ContentType,
				Content:     f.Content,
				Generated:   f.Generated.AsTime(),
			})
		}
		uDiag = append(uDiag, client.DiagnosticUnitResult{
			ComponentID: diag.Component.ID,
			UnitID:      diag.Unit.ID,
			UnitType:    diag.Unit.Type,
			Err:         diag.Err,
			Results:     files,
		})
	}

	var b bytes.Buffer
	err := diagnostics.ZipArchive(b, aDiag, uDiag) // TODO Do we want to pass a buffer/a reader around? or write the file to a temp dir and read (to avoid memory usage)? file usage may need more thought for containerized deployments
	if err != nil {
		return fmt.Errorf("error creating diagnostics bundle: %w", err)
	}

	err = h.uploader.UploadDiagnostics(ctx, action.ActionID, &b)
	_ = ack.Ack(ctx, action) // TODO ack should have the file upload ID in it
	if err != nil {
		return fmt.Errorf("unable to upload diagnostics: %w", err)
	}
	return nil
}
