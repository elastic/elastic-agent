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

// NewHandlerAckWithAcker takes an acker, a function that for each actionID must
// return the expected AckResponseItem for that action and if this ack errored
// or not.
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
				Message:    fmt.Sprintf("agent %q not found", agentID),
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

// NewHandlerEnroll returns an enrol handler ready to be used. Its repose will
// use the agentID, policyID and apiKey when building the EnrollResponse.
func NewHandlerEnroll(agentID, policyID string, apiKey APIKey) func(
	ctx context.Context,
	h *Handlers,
	userAgent string,
	enrollRequest EnrollRequest) (*EnrollResponse, *HTTPError) {
	return func(
		ctx context.Context,
		h *Handlers,
		userAgent string,
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

// NewHandlerCheckin returns a checkin handler that always returns a policy with
// System integrations and, if withEndpoint is true, Endpoint Security.
func NewHandlerCheckin(ackToken string) func(
	ctx context.Context,
	h *Handlers,
	agentID string,
	userAgent string,
	acceptEncoding string,
	checkinRequest CheckinRequest) (*CheckinResponse, *HTTPError) {

	policy := checkinResponseJSONPolicySystemIntegration

	return func(
		ctx context.Context,
		h *Handlers,
		agentID string,
		userAgent string,
		acceptEncoding string,
		checkinRequest CheckinRequest) (*CheckinResponse, *HTTPError) {
		h.AgentID = agentID

		resp := CheckinResponse{}
		err := json.Unmarshal(
			[]byte(fmt.Sprintf(policy, ackToken, agentID)),
			&resp)
		if err != nil {
			return nil, &HTTPError{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to unmarshal policy PolicySystemIntegration: %v", err),
			}
		}

		return &resp, nil
	}
}

// CheckinAction is the actions to be sent on next checkin and the delay, how
// long the handler will wait before sending the response.
type CheckinAction struct {
	AckToken string
	Actions  []string
	Delay    time.Duration
}

// NewHandlerCheckinFakeComponent takes a generator function that returns the
// actions to be sent on the next checkin. The actions format is a JSON list.
// E.g.:
//   - ["action1", "action2"]
//   - ["action1"]
//   - []
func NewHandlerCheckinFakeComponent(next func() (CheckinAction, *HTTPError)) func(
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

		actions := fmt.Sprintf("[%s]", strings.Join(data.Actions, ","))

		respStr := NewCheckinResponse(actions)
		respStr := NewCheckinResponse(data.AckToken, actions)
		resp := CheckinResponse{}
		err := json.Unmarshal(
			[]byte(respStr),
			&resp)
		if err != nil {
			return nil, &HTTPError{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to unmarshal policy: %v", err),
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
