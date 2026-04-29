// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import (
	"bytes"
	"context"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/pkg/fleetcontract"
)

// EnrollRequest is the data required to enroll the elastic-agent into Fleet Server.
//
// Example:
// POST /api/fleet/agents/enroll
//
//	 {
//		  "type": "PERMANENT",
//		  "id": "custom-id", // optional
//		  "replace_token": "replacetokenvalue", // optional
//		  "metadata": {
//		    "local": { "os": "macos"},
//		    "user_provided": { "region": "us-east"}
//		  }
//		}
type EnrollRequest struct {
	EnrollAPIKey string                   `json:"-"`
	Type         fleetcontract.EnrollType `json:"type"`
	ID           string                   `json:"id"`
	ReplaceToken string                   `json:"replace_token"`
	Metadata     Metadata                 `json:"metadata"`
}

// Metadata is a all the metadata send or received from the elastic-agent.
type Metadata struct {
	Local        *info.ECSMeta          `json:"local"`
	UserProvided map[string]interface{} `json:"user_provided"`
	Tags         []string               `json:"tags"`
}

// Validate validates the enrollment request before sending it to the API.
func (e *EnrollRequest) Validate() error {
	var errs []error

	if len(e.EnrollAPIKey) == 0 {
		errs = append(errs, errors.New("missing enrollment api key"))
	}

	if len(e.Type) == 0 {
		errs = append(errs, errors.New("missing enrollment type"))
	}

	return goerrors.Join(errs...)
}

// EnrollCmd is the command to be executed to enroll an elastic-agent into Fleet Server.
type EnrollCmd struct {
	client client.Sender
}

// Execute enroll the Agent in the Fleet Server.
func (e *EnrollCmd) Execute(ctx context.Context, r *EnrollRequest) (*fleetcontract.EnrollResponse, error) {
	const p = "/api/fleet/agents/enroll"
	const key = "Authorization"
	const prefix = "ApiKey "

	if err := r.Validate(); err != nil {
		return nil, err
	}

	headers := map[string][]string{
		key: {prefix + r.EnrollAPIKey},
	}

	b, err := json.Marshal(r)
	if err != nil {
		return nil, errors.New(err, "fail to encode the enrollment request")
	}

	resp, err := e.client.Send(ctx, "POST", p, nil, headers, bytes.NewBuffer(b))
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fleetcontract.ErrConnRefused
		}

		var et *url.Error
		if errors.As(err, &et) {
			return nil, et.Err
		}

		var netOp *net.OpError
		if errors.As(err, &netOp) {
			return nil, fleetcontract.ErrConnRefused
		}

		return nil, errors.New(err,
			"fail to execute request to fleet-server",
			errors.TypeNetwork)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fleetcontract.ErrTooManyRequests
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fleetcontract.ErrInvalidToken
	}

	if status, temporary := fleetcontract.TemporaryServerErrorCodes[resp.StatusCode]; temporary {
		return nil, fmt.Errorf("received status code %d (%s): %w", resp.StatusCode, status, fleetcontract.ErrTemporaryServerError)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, client.ExtractError(resp.Body)
	}

	enrollResponse := &fleetcontract.EnrollResponse{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(enrollResponse); err != nil {
		return nil, errors.New(err, "fail to decode enrollment response")
	}

	if err := enrollResponse.Validate(); err != nil {
		return nil, err
	}

	return enrollResponse, nil
}

// NewEnrollCmd creates a new EnrollCmd.
func NewEnrollCmd(client client.Sender) *EnrollCmd {
	return &EnrollCmd{client: client}
}
