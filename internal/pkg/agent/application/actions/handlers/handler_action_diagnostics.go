// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/control/v2/client"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Uploader is the interface used to upload a diagnostics bundle to fleet-server.
type Uploader interface {
	UploadDiagnostics(context.Context, string, *bytes.Buffer) (string, error)
}

// Diagnostics is the handler to process Diagnostics actions.
// When a Diagnostics action is received a full diagnostics bundle is taken and uploaded to fleet-server.
type Diagnostics struct {
	log      *logger.Logger
	client   client.Client
	uploader Uploader
}

// NewDiagnostics returns a new Diagnostics handler.
func NewDiagnostics(log *logger.Logger, uploader Uploader) *Diagnostics {
	return &Diagnostics{
		log:      log,
		client:   client.New(),
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
	defer ack.Ack(ctx, action) //nolint:errcheck // no path for a failed ack

	if err := h.client.Connect(ctx); err != nil {
		action.Err = err
		return fmt.Errorf("failed to connect to control server: %w", err)
	}

	h.log.Debug("Gathering agent diagnostics.")
	// Gather agent diagnostics
	aDiag, err := h.client.DiagnosticAgent(ctx)
	if err != nil {
		action.Err = err
		return fmt.Errorf("unable to gather agent diagnostics: %w", err)
	}
	h.log.Debug("Gathering unit diagnostics.")
	uDiag, err := h.client.DiagnosticUnits(ctx)
	if err != nil {
		action.Err = err
		return fmt.Errorf("unable to gather unit diagnostics: %w", err)
	}

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
	err = diagnostics.ZipArchive(&wBuf, &b, aDiag, uDiag) // TODO Do we want to pass a buffer/a reader around? or write the file to a temp dir and read (to avoid memory usage)? file usage may need more thought for containerized deployments
	if err != nil {
		action.Err = err
		return fmt.Errorf("error creating diagnostics bundle: %w", err)
	}

	h.log.Debug("Sending diagnostics archive.")
	uploadID, err := h.uploader.UploadDiagnostics(ctx, ts.Format("2006-01-02T15-04-05Z07-00"), &b) // RFC3339 format that uses - instead of : so it works on Windows
	action.Err = err
	action.UploadID = uploadID
	if err != nil {
		return fmt.Errorf("unable to upload diagnostics: %w", err)
	}
	h.log.Debugf("Diagnostics action '%+v' complete.", a)
	return nil
}
