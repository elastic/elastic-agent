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

	"github.com/google/uuid"
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
	agentID string,
	ackRequest AckRequest) (*AckResponse, *HTTPError) {
	return func(ctx context.Context, agentID string, ackRequest AckRequest) (*AckResponse, *HTTPError) {
		resp := AckResponse{Action: "action"}
		for range ackRequest.Events {
			resp.Items = append(resp.Items, AckResponseItem{
				Status:  http.StatusOK,
				Message: http.StatusText(http.StatusOK),
			})
		}

		return &resp, nil
	}
}
func NewHandlerEnroll(policyID string, apiKey APIKey) func(
	ctx context.Context,
	userAgent string,
	enrollRequest EnrollRequest) (*EnrollResponse, *HTTPError) {

	return func(ctx context.Context, userAgent string, enrollRequest EnrollRequest) (*EnrollResponse, *HTTPError) {
		localMetadata, err := json.Marshal(enrollRequest.Metadata)
		if err != nil {
			return nil, &HTTPError{
				StatusCode: http.StatusInternalServerError,
				Message:    http.StatusText(http.StatusInternalServerError),
				Status: fmt.Sprintf(
					"could not marshal enroll request metadata into JSON: %v",
					err),
			}
		}

		agentID, err := uuid.NewUUID()
		if err != nil {
			return nil, &HTTPError{
				StatusCode: http.StatusInternalServerError,
				Status: fmt.Sprintf(
					"could not create agentID: %v",
					err),
			}
		}

		return &EnrollResponse{
			Action: "created",
			Item: EnrollResponseItem{
				AgentID:              agentID.String(),
				Active:               true,
				PolicyID:             policyID,
				Type:                 "PERMANENT",
				EnrolledAt:           time.Now().Format(time.RFC3339),
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
	agentID string,
	userAgent string,
	acceptEncoding string,
	checkinRequest CheckinRequest) (*CheckinResponse, *HTTPError) {

	policy := checkinResponseJSONPolicySystemIntegration

	return func(
		ctx context.Context,
		agentID string,
		userAgent string,
		acceptEncoding string,
		checkinRequest CheckinRequest) (*CheckinResponse, *HTTPError) {

		// TODO: add output
		// data:= DataFromCtx(ctx)
		resp := CheckinResponse{}
		err := json.Unmarshal(
			[]byte(fmt.Sprintf(policy, ackToken, agentID)),
			&resp)
		if err != nil {
			return nil, &HTTPError{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to unmarshal policy: %v", err),
			}
		}

		return &resp, nil
	}
}

func NewHandlerStatusHealth() func(ctx context.Context) (*StatusResponse, *HTTPError) {
	return func(ctx context.Context) (*StatusResponse, *HTTPError) {
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
