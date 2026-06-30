// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	pkgfleetapi "github.com/elastic/elastic-agent/pkg/fleetapi"
)

const ackPath = "/api/fleet/agents/%s/acks"

// AckEvent is re-exported from pkg/fleetapi for backward compatibility.
type AckEvent = pkgfleetapi.AckEvent

// AckRequest is re-exported from pkg/fleetapi for backward compatibility.
type AckRequest = pkgfleetapi.AckRequest

// AckResponseItem is re-exported from pkg/fleetapi for backward compatibility.
type AckResponseItem = pkgfleetapi.AckResponseItem

// AckResponse is re-exported from pkg/fleetapi for backward compatibility.
type AckResponse = pkgfleetapi.AckResponse

// AckCmd is a fleet API command.
type AckCmd struct {
	client client.Sender
	info   pkgfleetapi.AgentInfo
}

// NewAckCmd creates a new api command.
func NewAckCmd(info pkgfleetapi.AgentInfo, client client.Sender) *AckCmd {
	return &AckCmd{
		client: client,
		info:   info,
	}
}

// Execute ACK of actions to the Fleet.
func (e *AckCmd) Execute(ctx context.Context, r *AckRequest) (_ *AckResponse, err error) {
	span, ctx := apm.StartSpan(ctx, "execute", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()
	if err := r.Validate(); err != nil {
		return nil, err
	}

	b, err := json.Marshal(r)
	if err != nil {
		return nil, errors.New(err,
			"fail to encode the ack request",
			errors.TypeUnexpected)
	}

	ap := fmt.Sprintf(ackPath, e.info.AgentID())
	resp, err := e.client.Send(ctx, "POST", ap, nil, nil, bytes.NewReader(b))
	if err != nil {
		return nil, errors.New(err,
			"fail to ack to fleet",
			errors.TypeNetwork,
			errors.M(errors.MetaKeyURI, ap))
	}
	defer resp.Body.Close()

	// Read ack response always it can be sent with any status code.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ackResponse AckResponse
	if err := json.Unmarshal(body, &ackResponse); err != nil {
		return nil, errors.New(err,
			"fail to decode ack response",
			errors.TypeNetwork,
			errors.M(errors.MetaKeyURI, ap))
	}

	// if action is not "acks", try to extract the error
	if ackResponse.Action != "acks" {
		return nil, client.ExtractError(bytes.NewReader(body))
	}

	return &ackResponse, nil
}
