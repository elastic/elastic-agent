// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/control/v2/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/control/v2/cproto"
	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	"golang.org/x/time/rate"
)

// ErrRateLimit is the rate limit error that is returned if the handler is ran too often.
// This may occur if the user sends multiple diagnostics actions to an agent in a short duration
// or if the agent goes offline and retrieves multiple diagnostics actions.
// In either case the 1st action will succeed and the others will ack with an the error.
var ErrRateLimit = fmt.Errorf("rate limit exceeded")

// Uploader is the interface used to upload a diagnostics bundle to fleet-server.
type Uploader interface {
	UploadDiagnostics(context.Context, string, string, *bytes.Buffer) (string, error)
}

// Diagnostics is the handler to process Diagnostics actions.
// When a Diagnostics action is received a full diagnostics bundle is taken and uploaded to fleet-server.
type Diagnostics struct {
	log      *logger.Logger
	coord    *coordinator.Coordinator
	limiter  *rate.Limiter
	uploader Uploader
}

// NewDiagnostics returns a new Diagnostics handler.
func NewDiagnostics(log *logger.Logger, coord *coordinator.Coordinator, cfg config.Limit, uploader Uploader) *Diagnostics {
	return &Diagnostics{
		log:      log,
		coord:    coord,
		limiter:  rate.NewLimiter(rate.Every(cfg.Interval), cfg.Burst),
		uploader: uploader,
	}
}

// Handle processes the passed Diagnostics action.
func (h *Diagnostics) Handle(ctx context.Context, a fleetapi.Action, ack acker.Acker) error {
	h.log.Debugf("handlerDiagnostics: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionDiagnostics)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionDiagnostics and received %T", a)
	}
	ts := time.Now().UTC()
	defer func() {
		ack.Ack(ctx, action) //nolint:errcheck // no path for a failed ack
		ack.Commit(ctx)      //nolint:errcheck //no path for failing a commit
	}()

	if !h.limiter.Allow() {
		action.Err = ErrRateLimit
		return ErrRateLimit
	}

	h.log.Debug("Gathering agent diagnostics.")
	aDiag, err := h.runHooks(ctx)
	if err != nil {
		action.Err = err
		return fmt.Errorf("unable to gather agent diagnostics: %w", err)
	}
	h.log.Debug("Gathering unit diagnostics.")
	uDiag := h.diagUnits(ctx)

	var b bytes.Buffer
	// create a buffer that any redaction error messages are written into as warnings.
	// if the buffer is not empty after the bundle is assembled then the message is written to the log
	// zapio.Writer would be a better way to pass a writer to ZipArchive, but logp embeds the zap.Logger so we are unable to access it here.
	var wBuf bytes.Buffer
	defer func() {
		if str := wBuf.String(); str != "" {
			h.log.Warn(str)
		}
	}()
	h.log.Debug("Assembling diagnostics archive.")
	err = diagnostics.ZipArchive(&wBuf, &b, aDiag, uDiag)
	if err != nil {
		action.Err = err
		return fmt.Errorf("error creating diagnostics bundle: %w", err)
	}

	h.log.Debug("Sending diagnostics archive.")
	uploadID, err := h.uploader.UploadDiagnostics(ctx, action.ActionID, ts.Format("2006-01-02T15-04-05Z07-00"), &b) // RFC3339 format that uses - instead of : so it works on Windows
	action.Err = err
	action.UploadID = uploadID
	if err != nil {
		return fmt.Errorf("unable to upload diagnostics: %w", err)
	}
	h.log.Debugf("Diagnostics action '%+v' complete.", a)
	return nil
}

func (h *Diagnostics) runHooks(ctx context.Context) ([]client.DiagnosticFileResult, error) {
	hooks := append(h.coord.DiagnosticHooks(), diagnostics.GlobalHooks()...)
	diags := make([]client.DiagnosticFileResult, 0, len(hooks))
	for _, hook := range hooks {
		if ctx.Err() != nil {
			return diags, ctx.Err()
		}
		diags = append(diags, client.DiagnosticFileResult{
			Name:        hook.Name,
			Filename:    hook.Filename,
			Description: hook.Description,
			ContentType: hook.ContentType,
			Content:     hook.Hook(ctx),
			Generated:   time.Now().UTC(),
		})
	}
	return diags, nil
}

func (h *Diagnostics) diagUnits(ctx context.Context) []client.DiagnosticUnitResult {
	uDiag := make([]client.DiagnosticUnitResult, 0)
	rr := h.coord.PerformDiagnostics(ctx)
	for _, r := range rr {
		diag := client.DiagnosticUnitResult{
			ComponentID: r.Component.ID,
			UnitID:      r.Unit.ID,
			UnitType:    cproto.UnitType(r.Unit.Type),
		}
		if r.Err != nil {
			diag.Err = r.Err
		} else {
			results := make([]client.DiagnosticFileResult, 0, len(r.Results))
			for _, res := range r.Results {
				results = append(results, client.DiagnosticFileResult{
					Name:        res.Name,
					Filename:    res.Filename,
					Description: res.Description,
					ContentType: res.ContentType,
					Content:     res.Content,
					Generated:   res.Generated.AsTime(),
				})
			}
			diag.Results = results
		}
		uDiag = append(uDiag, diag)
	}
	return uDiag
}
