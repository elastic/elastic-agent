// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"

	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"

	"golang.org/x/time/rate"
)

// ErrRateLimit is the rate limit error that is returned if the handler is ran too often.
// This may occur if the user sends multiple diagnostics actions to an agent in a short duration
// or if the agent goes offline and retrieves multiple diagnostics actions.
// In either case the 1st action will succeed and the others will ack with an the error.
var ErrRateLimit = fmt.Errorf("rate limit exceeded")

// Uploader is the interface used to upload a diagnostics bundle to fleet-server.
type Uploader interface {
	UploadDiagnostics(context.Context, string, string, int64, io.Reader) (string, error)
}

// diagnosticsProvider abstracts the source of the diagnostic data
type diagnosticsProvider interface {
	DiagnosticHooks() diagnostics.Hooks
	PerformDiagnostics(ctx context.Context, req ...runtime.ComponentUnitDiagnosticRequest) []runtime.ComponentUnitDiagnostic
}

// abstractLogger represents a logger implementation
type abstractLogger interface {
	Debug(args ...interface{})
	Debugf(template string, args ...interface{})
	Debugw(msg string, keysAndValues ...interface{})
	Infof(template string, args ...interface{})
	Warn(args ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Errorf(template string, args ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
}

// Diagnostics is the handler to process Diagnostics actions.
// When a Diagnostics action is received a full diagnostics bundle is taken and uploaded to fleet-server.
type Diagnostics struct {
	log          abstractLogger
	diagProvider diagnosticsProvider
	limiter      *rate.Limiter
	uploader     Uploader
}

// NewDiagnostics returns a new Diagnostics handler.
func NewDiagnostics(log abstractLogger, coord diagnosticsProvider, cfg config.Limit, uploader Uploader) *Diagnostics {
	return &Diagnostics{
		log:          log,
		diagProvider: coord,
		limiter:      rate.NewLimiter(rate.Every(cfg.Interval), cfg.Burst),
		uploader:     uploader,
	}
}

// Handle processes the passed Diagnostics action asynchronously.
//
// The handler has a rate limiter to limit the number of diagnostics actions that are run at once.
func (h *Diagnostics) Handle(ctx context.Context, a fleetapi.Action, ack acker.Acker) error {
	h.log.Debugf("handlerDiagnostics: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionDiagnostics)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionDiagnostics and received %T", a)
	}
	go h.collectDiag(ctx, action, ack)
	return nil
}

// collectDiag will attempt to assemble a diagnostics bundle and upload it with the file upload APIs on fleet-server.
//
// The bundle is assembled on disk, however if it encounters any errors an in-memory-buffer is used.
func (h *Diagnostics) collectDiag(ctx context.Context, action *fleetapi.ActionDiagnostics, ack acker.Acker) {
	ts := time.Now().UTC()
	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("panic detected: %v", r)
			action.Err = err
			h.log.Errorw("diagnostics handler panicked", "error.message", err)
		}
	}()
	defer func() {
		err := ack.Ack(ctx, action)
		if err != nil {
			h.log.Errorw("failed to ack diagnostics action",
				"error.message", err,
				"action", action)
		}
		err = ack.Commit(ctx)
		if err != nil {
			h.log.Errorw("failed to commit diagnostics action",
				"error.message", err,
				"action", action)

		}
	}()

	if !h.limiter.Allow() {
		action.Err = ErrRateLimit
		h.log.Infof("diagnostics action handler rate limited: %v", ErrRateLimit)
		return
	}

	h.log.Debug("Gathering agent diagnostics.")
	aDiag, err := h.runHooks(ctx)
	if err != nil {
		action.Err = err
		h.log.Errorw("diagnostics action handler failed to run diagnostics hooks",
			"error.message", err,
			"action", action)
		return
	}
	h.log.Debug("Gathering unit diagnostics.")
	uDiag := h.diagUnits(ctx)

	var r io.Reader
	// attempt to create the a temporary diagnostics file on disk in order to avoid loading a
	// potentially large file in memory.
	// if on-disk creation fails an in-memory buffer is used.
	f, s, err := h.diagFile(aDiag, uDiag)
	if err != nil {
		var b bytes.Buffer
		h.log.Warnw("Diagnostics action unable to use temporary file, using buffer instead.", "error.message", err)
		var wBuf bytes.Buffer
		defer func() {
			if str := wBuf.String(); str != "" {
				h.log.Warn(str)
			}
		}()
		// NOTE: Right now, actions don't support component-level diagnostics
		err := diagnostics.ZipArchive(&wBuf, &b, aDiag, uDiag, []client.DiagnosticComponentResult{})
		if err != nil {
			h.log.Errorw(
				"diagnostics action handler failed generate zip archive",
				"error.message", err,
				"action", action,
			)
			action.Err = err
			return
		}
		r = &b
		s = int64(b.Len())
	} else {
		defer func() {
			f.Close()
			os.Remove(f.Name())
		}()
		r = f
	}
	h.log.Debug("Sending diagnostics archive.")
	uploadID, err := h.uploader.UploadDiagnostics(ctx, action.ActionID, ts.Format("2006-01-02T15-04-05Z07-00"), s, r) // RFC3339 format that uses - instead of : so it works on Windows
	action.UploadID = uploadID
	if err != nil {
		action.Err = err
		h.log.Errorw(
			"diagnostics action handler failed to upload diagnostics",
			"error.message", err,
			"action", action)
		return
	}
	elapsed := time.Since(ts)
	h.log.Debugw(fmt.Sprintf("Diagnostics action complete. Took %s", elapsed), "action", action, "elapsed", elapsed)
}

// runHooks runs the agent diagnostics hooks.
func (h *Diagnostics) runHooks(ctx context.Context) ([]client.DiagnosticFileResult, error) {
	hooks := append(h.diagProvider.DiagnosticHooks(), diagnostics.GlobalHooks()...)
	diags := make([]client.DiagnosticFileResult, 0, len(hooks))
	for _, hook := range hooks {
		if ctx.Err() != nil {
			return diags, ctx.Err()
		}
		h.log.Debugw(fmt.Sprintf("Executing hook %s", hook.Name), "hook", hook.Name, "filename", hook.Filename)
		startTime := time.Now()
		diags = append(diags, client.DiagnosticFileResult{
			Name:        hook.Name,
			Filename:    hook.Filename,
			Description: hook.Description,
			ContentType: hook.ContentType,
			Content:     hook.Hook(ctx),
			Generated:   time.Now().UTC(),
		})
		elapsed := time.Since(startTime)
		h.log.Debugw(fmt.Sprintf("Hook %s execution complete, took %s", hook.Name, elapsed.String()), "hook", hook.Name, "filename", hook.Filename, "elapsed", elapsed.String())
	}
	return diags, nil
}

// diagUnits gathers diagnostics from units.
func (h *Diagnostics) diagUnits(ctx context.Context) []client.DiagnosticUnitResult {
	uDiag := make([]client.DiagnosticUnitResult, 0)
	h.log.Debug("Performing unit diagnostics")
	startTime := time.Now()
	defer func() {
		h.log.Debugf("Unit diagnostics complete. Took: %s", time.Since(startTime))
	}()
	rr := h.diagProvider.PerformDiagnostics(ctx)
	h.log.Debug("Collecting results of unit diagnostics")
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

// diagFile will write the diagnostics to a temporary file and return the file ready to be read
func (h *Diagnostics) diagFile(aDiag []client.DiagnosticFileResult, uDiag []client.DiagnosticUnitResult) (*os.File, int64, error) {
	f, err := os.CreateTemp("", "elastic-agent-diagnostics")
	if err != nil {
		return nil, 0, err
	}

	name := f.Name()
	var wBuf bytes.Buffer
	defer func() {
		if str := wBuf.String(); str != "" {
			h.log.Warn(str)
		}
	}()
	if err := diagnostics.ZipArchive(&wBuf, f, aDiag, uDiag, []client.DiagnosticComponentResult{}); err != nil {
		os.Remove(name)
		return nil, 0, err
	}
	_ = f.Sync()

	_, err = f.Seek(0, 0)
	if err != nil {
		os.Remove(name)
		return nil, 0, err
	}

	fi, err := f.Stat()
	if err != nil {
		os.Remove(name)
		return nil, 0, err
	}
	return f, fi.Size(), nil
}
