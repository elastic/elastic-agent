// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
)

// ReqError is an error wrapper to wrap errors with a request.
// These can include validation or marshalling errors that should not be retried.
type ReqError struct {
	err error
}

func (e *ReqError) Error() string {
	return e.err.Error()
}

func (e *ReqError) Unwrap() error {
	return e.err
}

const auditUnenrollPath = "/api/fleet/agents/%s/audit/unenroll"

type Reason string

const (
	ReasonUninstall Reason = "uninstall"
)

type AuditUnenrollRequest struct {
	Reason    Reason    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// Validate will ensure the timestamp is set and the reason is an allowed value.
func (e *AuditUnenrollRequest) Validate() error {
	if e.Timestamp.IsZero() {
		return &ReqError{fmt.Errorf("request timestamp not set")}
	}
	switch e.Reason {
	case ReasonUninstall:
	default:
		return &ReqError{fmt.Errorf("unsupported reason: %s", e.Reason)}
	}
	return nil
}

type AuditUnenrollCmd struct {
	client client.Sender
	info   agentInfo
}

func NewAuditUnenrollCmd(info agentInfo, client client.Sender) *AuditUnenrollCmd {
	return &AuditUnenrollCmd{
		client: client,
		info:   info,
	}
}

// Execute sends the request to fleet-sever and returns the response.
//
// the caller must determine if the call succeeded or if it should be retried.
func (e *AuditUnenrollCmd) Execute(ctx context.Context, r *AuditUnenrollRequest) (*http.Response, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	p, err := json.Marshal(r)
	if err != nil {
		return nil, &ReqError{err}
	}
	path := fmt.Sprintf(auditUnenrollPath, e.info.AgentID())
	resp, err := e.client.Send(ctx, http.MethodPost, path, nil, nil, bytes.NewBuffer(p))
	if err != nil {
		// Invalid credentials should result in no retries
		if errors.Is(err, client.ErrInvalidAPIKey) {
			return nil, &ReqError{
				err: err,
			}
		}
		return nil, errors.New(err,
			"fail to notify audit/unenroll on fleet-server",
			errors.TypeNetwork,
			errors.M(errors.MetaKeyURI, path))
	}
	return resp, nil
}
