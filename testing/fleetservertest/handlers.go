// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetservertest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	PathAgentAcks    = "/api/fleet/agents/{id}/acks"
	PathAgentCheckin = "/api/fleet/agents/{id}/checkin"
	PathAgentEnroll  = "/api/fleet/agents/enroll"

	PathArtifact = "/api/fleet/artifacts/{id}/{sha2}"
	PathStatus   = "/api/status"

	PathUploadBegin    = "/api/fleet/uploads"
	PathUploadChunk    = "/api/fleet/uploads/{id}/{chunkNum}"
	PathUploadComplete = "/api/fleet/uploads/{id}"
)

func NewPathAgentAcks(agentID string) string {
	return strings.Replace(PathAgentAcks, "{id}", agentID, 1)
}

func NewPathCheckin(agentID string) string {
	return strings.Replace(PathAgentCheckin, "{id}", agentID, 1)
}

func NewPathArtifact(agentID, sha2 string) string {
	return strings.Replace(
		strings.Replace(PathArtifact, "{id}", agentID, 1),
		"{sha2}",
		sha2,
		1)
}

func NewPathUploadBegin() string {
	return PathUploadBegin
}

func NewPathUploadChunk(agentID, chunkNum string) string {
	return strings.Replace(
		strings.Replace(PathUploadChunk, "{id}", agentID, 1),
		"{chunkNum}",
		chunkNum,
		1)
}

func NewPathUploadComplete(agentID string) string {
	return strings.Replace(PathUploadComplete, "{id}", agentID, 1)
}

func NewHandlerAck() func(
	ctx context.Context,
	h *Handlers,
	agentID string,
	ackRequest AckRequest) (*AckResponse, *HTTPError) {
	return func(
		ctx context.Context,
		h *Handlers,
		agentID string,
		ackRequest AckRequest) (*AckResponse, *HTTPError) {
		resp := AckResponse{Action: "acks"}
		for range ackRequest.Events {
			resp.Items = append(resp.Items, AckResponseItem{
				Status:  http.StatusOK,
				Message: http.StatusText(http.StatusOK),
			})
		}

		return &resp, nil
	}
}

// Acker is a function that for each actionID must return a AckResponseItem for
// that action and if this ack errored or not.
type Acker func(actionID string) (AckResponseItem, bool)

// NewHandlerAckWithAcker takes an acker, a function that for each actionID must
// return the expected AckResponseItem for that action and if this ack errored
// or not.
// TODO(Anderson): fix me
func NewHandlerAckWithAcker(acker func(actionID string) (AckResponseItem, bool)) func(
	ctx context.Context,
	h *Handlers,
	agentID string,
	ackRequest AckRequest) (*AckResponse, *HTTPError) {
	return func(
		ctx context.Context,
		h *Handlers,
		agentID string,
		ackRequest AckRequest) (*AckResponse, *HTTPError) {
		if agentID != h.AgentID {
			return nil, &HTTPError{
				StatusCode: http.StatusNotFound,
				Message: fmt.Sprintf("agent %q not found, expecting %q",
					agentID, h.AgentID),
			}
		}

		resp := AckResponse{Action: "acks"}

		for _, e := range ackRequest.Events {
			r, isErr := acker(e.ActionId)
			resp.Errors = resp.Errors || isErr
			resp.Items = append(resp.Items, r)
		}

		return &resp, nil
	}
}

// NewHandlerEnroll returns an enrol handler ready to be used. It ignores the
// enrolment token. Its repose will use the provided agentID, policyID and apiKey
// when building the EnrollResponse. It'll also set the agentID on Handlers, which
// is accessible by the other handlers.
func NewHandlerEnroll(agentID, policyID string, apiKey APIKey) func(
	ctx context.Context,
	h *Handlers,
	userAgent string,
	enrolmentToken string,
	enrollRequest EnrollRequest) (*EnrollResponse, *HTTPError) {
	return func(
		ctx context.Context,
		h *Handlers,
		userAgent string,
		enrolmentToken string,
		enrollRequest EnrollRequest) (*EnrollResponse, *HTTPError) {

		h.AgentID = agentID

		localMetadata, err := json.Marshal(enrollRequest.Metadata.Local)
		if err != nil {
			return nil, &HTTPError{
				StatusCode: http.StatusInternalServerError,
				Message: fmt.Sprintf(
					"could not marshal enroll request metadata into JSON: %v",
					err),
			}
		}

		localMetadata, err = updateLocalMetaAgentID(localMetadata, agentID)
		if err != nil {
			return nil, &HTTPError{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("could not update local metadata: %v", err),
			}
		}

		return &EnrollResponse{
			Action: "created",
			Item: EnrollResponseItem{
				AgentID:              agentID,
				Active:               true,
				PolicyID:             policyID,
				Type:                 "PERMANENT",
				EnrolledAt:           timeNow().Format(time.RFC3339),
				UserProvidedMetadata: nil,
				LocalMetadata:        localMetadata,
				Actions:              nil,
				AccessApiKeyID:       apiKey.ID,
				AccessApiKey:         apiKey.Key,
				Status:               "online",
				Tags:                 enrollRequest.Metadata.Tags,
			},
		}, nil
	}
}

// CheckinAction is the actions to be sent on next checkin and the delay, how
// long the handler will wait before sending the response.
type CheckinAction struct {
	AckToken string
	Actions  []string
	Delay    time.Duration
}

// ActionsGenerator is a function which upon call returns the actions the
// checkin handler will add to its repose to the Elastic Agent.
// The actions format is a JSON list.
// E.g.:
//   - ["action1", "action2"]
//   - ["action1"]
//   - []
type ActionsGenerator func() (CheckinAction, *HTTPError)

// NewHandlerCheckin takes an ActionsGenerator which is used to populate the
// actions in the CheckinResponse.
func NewHandlerCheckin(next ActionsGenerator) func(
	ctx context.Context,
	h *Handlers,
	agentID string,
	userAgent string,
	acceptEncoding string,
	checkinRequest CheckinRequest) (*CheckinResponse, *HTTPError) {

	return func(
		ctx context.Context,
		h *Handlers,
		agentID string,
		userAgent string,
		acceptEncoding string,
		checkinRequest CheckinRequest) (*CheckinResponse, *HTTPError) {
		if agentID != h.AgentID {
			return nil, &HTTPError{
				StatusCode: http.StatusNotFound,
				Message:    fmt.Sprintf("agent %q not found", agentID),
			}
		}

		data, hErr := next()
		if hErr != nil {
			return nil, hErr
		}

		respStr := NewCheckinResponse(data.AckToken, data.Actions...)
		resp := CheckinResponse{}
		err := json.Unmarshal(
			[]byte(respStr),
			&resp)
		if err != nil {
			return nil, &HTTPError{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to CheckinResponse: %v", err),
			}
		}

		// simulate long pool
		time.Sleep(data.Delay)

		return &resp, nil
	}
}

func NewHandlerStatusHealth() func(ctx context.Context, _ *Handlers) (*StatusResponse, *HTTPError) {
	return func(ctx context.Context, _ *Handlers) (*StatusResponse, *HTTPError) {
		return &StatusResponse{
			Name:   "fleet-server",
			Status: "HEALTHY",
			// fleet-server does not respond with version information
		}, nil
	}
}

func NewHandlerStatusUnhealth() func(ctx context.Context) (*StatusResponse, *HTTPError) {
	return func(ctx context.Context) (*StatusResponse, *HTTPError) {
		return &StatusResponse{
			Name:   "fleet-server",
			Status: "UNHEALTHY",
			// fleet-server does not respond with version information
		}, &HTTPError{StatusCode: http.StatusInternalServerError}
	}
}
