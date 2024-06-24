// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetservertest

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// =============================================================================
// ================================== Ack ======================================
// =============================================================================

// AckRequest - The request an elastic-agent sends to fleet-serve to acknowledge the execution of one or more actions.
type AckRequest struct {
	Events []Event `json:"events"`
}

// AckResponse - Response to processing acknowledgement events.
type AckResponse struct {

	// The action result. Will have the value \"acks\".
	Action string `json:"action"`

	// A flag to indicate if one or more errors occurred when processing events.
	Errors bool `json:"errors"`

	// The in-order list of results from processing events.
	Items []AckResponseItem `json:"items"`
}

// AckResponseItem - The results of processing an acknowledgement event.
type AckResponseItem struct {

	// An HTTP status code that indicates if the event was processed successfully or not.
	Status int32 `json:"status"`

	// HTTP status text.
	Message string `json:"message,omitempty"`
}

// Event - The ack for a specific action that the elastic-agent has executed.
type Event struct {

	// The event type of the ack. Not used by fleet-server. Currently the elastic-agent will only generate ACTION_RESULT events.
	Type string `json:"type"`

	// The subtype of the ack event. Not used by fleet-server. Currently the elastic-agent will only generate ACKNOWLEDGED events.
	Subtype string `json:"subtype"`

	// The ID of the agent that executed the action.
	AgentId string `json:"agent_id"`

	// The action ID.
	ActionId string `json:"action_id"`

	// The input_type of the action for input actions.
	ActionInputType string `json:"action_input_type"`

	// Not used by the fleet-server.
	PolicyId string `json:"policy_id"`

	// Not used by the fleet-server.
	StreamId string `json:"stream_id"`

	// The timestamp of the acknowledgement event. Has the format of \"2006-01-02T15:04:05.99999-07:00\"
	Timestamp string `json:"timestamp"`

	// An acknowlegement message. The elastic-agent inserts the action ID and action type into this message.
	Message string `json:"message"`

	// An embedded JSON object that contains additional information for the fleet-server to process. Defined as a json.RawMessage in both the fleet-server and the elastic-agent.  Is currently used by UPGRADE actions to signal retries. If the error attribute is non empty payload is checked for `retry: bool` and `retry_attempt: int`. If retry is true, fleet-serve will mark the agent as retrying, if it's false the upgrade will be marked as failed.
	Payload string `json:"payload,omitempty"`

	// The time at which the action was started. Used only when acknowledging input actions.
	StartedAt string `json:"started_at"`

	// The time at which the action was completed. Used only when acknowledging input actions
	CompletedAt string `json:"completed_at"`

	// The action data for the input action being acknowledged.
	ActionData string `json:"action_data,omitempty"`

	// The action response for the input action being acknowledged.
	ActionResponse string `json:"action_response,omitempty"`

	// An embedded JSON object that has the data about the ack.  Used by REQUEST_DIAGNOSTICS actions. Contains a `upload_id` attribute used to communicate the successfully uploaded diagnostics ID.
	Data string `json:"data,omitempty"`

	// An error message. If this is non-empty an error has occurred when executing the action. For some actions (such as UPGRADE actions) it may result in the action being marked as failed.
	Error string `json:"error,omitempty"`
}

// =============================================================================
// ================================== Checkin ==================================
// =============================================================================

type CheckinRequest struct {

	// The agent state, inferred from agent control protocol states.
	Status string `json:"status"`

	// State message, may be overridden or use the error message of a failing component.
	Message string `json:"message"`

	// The ack_token form a previous response if the agent has checked in before. Translated to a sequence number in fleet-server in order to retrieve any new actions for the agent from the last checkin.
	AckToken string `json:"ack_token,omitempty"`

	// An embedded JSON object that holds meta-data values. Defined in fleet-server as a `json.RawMessage`, defined as an object in the elastic-agent. elastic-agent will populate the object with information from the binary and host/system environment. fleet-server will update the agent record if a checkin response contains different data from the record.
	LocalMetadata json.RawMessage `json:"local_metadata,omitempty"`

	// An embedded JSON object that holds component information that the agent is running. Defined in fleet-server as a `json.RawMessage`, defined as an object in the elastic-agent. fleet-server will update the components in an agent record if they differ from this object.
	Components json.RawMessage `json:"components,omitempty"`

	// An optional timeout value that informs fleet-server of when a client will time out on it's checkin request. If not specified fleet-server will use the timeout values specified in the config (defaults to 5m polling and a 10m write timeout). The value, if specified is expected to be a string that is parsable by [time.ParseDuration](https://pkg.go.dev/time#ParseDuration). If specified fleet-server will set its poll timeout to `max(1m, poll_timeout-2m)` and its write timeout to `max(2m, poll_timout-1m)`.
	PollTimeout string `json:"poll_timeout,omitempty"`
}
type CheckinResponse struct {

	// The acknowledgment token used to indicate action delivery.
	AckToken string `json:"ack_token,omitempty"`

	// The action result. Set to \"checkin\".
	Action string `json:"action"`

	// A list of actions that the agent must execute.
	Actions []Action `json:"actions,omitempty"`
}

// Action - An action for an elastic-agent. The actions are defined in generic terms on the fleet-server. The elastic-agent will have additional details for what is expected when a specific action-type is received. Many attributes in this schema also contain yaml tags so the elastic-agent may serialize them. The structure of the `data` attribute will vary between action types.  An additional consideration is Scheduled Actions. Scheduled actions are currently defined as actions that have non-empty values for both the `start_time` and `expiration` attributes.
type Action struct {

	// The agent ID.
	AgentId string `json:"agent_id"`

	// Time when the action was created.
	CreatedAt string `json:"created_at"`

	// The earliest execution time for the action. Agent will not execute the action before this time. Used for scheduled actions.
	StartTime string `json:"start_time,omitempty" yaml:"start_time"`

	// The latest start time for the action. Actions will be dropped by the agent if execution has not started by this time. Used for scheduled actions.
	Expiration string `json:"expiration,omitempty" yaml:"expiration"`

	// An embedded action-specific object.
	Data *interface{} `json:"data" yaml:"data"`

	// The action ID.
	Id string `json:"id" yaml:"action_id"`

	// APM traceparent for the action.
	Traceparent string `json:"traceparent,omitempty" yaml:"traceparent"`

	// The action type.
	Type string `json:"type" yaml:"type"`

	// The input type of the action for actions with type `INPUT_ACTION`.
	InputType string `json:"input_type" yaml:"input_type"`

	// The timeout value (in seconds) for actions with type `INPUT_ACTION`.
	Timeout int64 `json:"timeout,omitempty" yaml:"timeout"`

	Signed ActionSignature `json:"signed,omitempty" yaml:"signed"`
}

// ActionSignature - Optional action signing data.
type ActionSignature struct {

	// The base64 encoded, UTF-8 JSON serialized action bytes that are signed.
	Data string `json:"data" yaml:"data"`

	// The base64 encoded signature.
	Signature string `json:"signature" yaml:"signature"`
}

// =============================================================================
// ================================== Enroll ===================================
// =============================================================================

// EnrollRequest - A request to enroll a new agent into fleet.
type EnrollRequest struct {

	// The enrollment type of the agent. The agent only supports the PERMANENT value
	Type string `json:"type"`

	// The shared ID of the agent. To support pre-existing installs. NOT YET IMPLEMENTED.
	SharedId string `json:"shared_id"`

	Metadata EnrollMetadata `json:"metadata"`
}

// EnrollResponse - The enrollment action response.
type EnrollResponse struct {

	// The action result. Will have the value \"created\".
	Action string `json:"action"`

	Item EnrollResponseItem `json:"item"`
}

// EnrollResponseItem - Response to a successful enrollment of an agent into fleet.
type EnrollResponseItem struct {

	// The agent ID
	AgentID string `json:"id"`

	// If the agent is active in fleet. Will be set to true upon enrollment.
	Active bool `json:"active"`

	// The policy ID that the agent is enrolled with. Decoded from the Handlers key used in the request.
	PolicyID string `json:"policy_id"`

	// The enrollment request type.
	Type string `json:"type"`

	// The RFC3339 timestamp that the agent was enrolled at.
	EnrolledAt string `json:"enrolled_at"`

	// A copy of the user provided metadata from the enrollment request. Currently will be empty.
	UserProvidedMetadata json.RawMessage `json:"user_provided_metadata"`

	// A copy of the (updated) local metadata provided in the enrollment request.
	LocalMetadata json.RawMessage `json:"local_metadata"`

	// Defined in fleet-server and elastic-agent as `[]interface{}` but never used.
	Actions []map[string]interface{} `json:"actions"`

	// The id of the ApiKey that fleet-server has generated for the enrolling agent.
	AccessApiKeyID string `json:"access_api_key_id"`

	// The ApiKey token that fleet-server has generated for the enrolling agent.
	AccessApiKey string `json:"access_api_key"`

	// Agent status from fleet-server. fleet-ui may differ.
	Status string `json:"status"`

	// A copy of the tags that were sent with the enrollment request.
	Tags []string `json:"tags"`
}

// EnrollMetadata - Metadata associated with the agent that is enrolling to fleet.
type EnrollMetadata struct {

	// An embedded JSON object that holds user-provided meta-data values. Defined in fleet-server as a `json.RawMessage`. fleet-server does not use these values on enrollment of an agent. Defined in the elastic-agent as a `map[string]interface{}` with no way to specify any values.
	UserProvided json.RawMessage `json:"user_provided"`

	// An embedded JSON object that holds meta-data values. Defined in fleet-server as a `json.RawMessage`, defined as an object in the elastic-agent. elastic-agent will populate the object with information from the binary and host/system environment. If not empty fleet-server will update the value of `local[\"elastic\"][\"agent\"][\"id\"]` to the agent ID (assuming the keys exist). The (possibly updated) value is sent by fleet-server when creating the record for a new agent.
	Local json.RawMessage `json:"local"`

	// User provided tags for the agent. fleet-server will pass the tags to the agent record on enrollment.
	Tags []string `json:"tags"`
}

// =============================================================================
// ================================== Status ===================================
// =============================================================================

// StatusResponse - Status response information.
type StatusResponse struct {

	// Service name.
	Name string `json:"name"`

	// A Unit state that fleet-server may report. Unit state is defined in the elastic-agent-client specification.
	Status string `json:"status"`

	Version *StatusResponseVersion `json:"version,omitempty"`
}

// StatusResponseVersion - Version information included in the response to an authorized status request.
type StatusResponseVersion struct {

	// The fleet-server version.
	Number string `json:"number,omitempty"`

	// The commit that the fleet-server was built from.
	BuildHash string `json:"build_hash,omitempty"`

	// The date-time that the fleet-server binary was created.
	BuildTime string `json:"build_time,omitempty"`
}

// =============================================================================
// ================================== Upload Begin =============================
// =============================================================================

type UploadBeginRequest struct {
	File UploadBeginRequestFile `json:"file"`

	// ID of the action that requested this file
	ActionId string `json:"action_id"`

	// Identifier of the agent uploading. Matches the ID usually found in agent.id
	AgentId string `json:"agent_id"`

	// The source integration sending this file
	Src string `json:"src"`
}

// UploadBeginResponse - Response to initiating a file upload
type UploadBeginResponse struct {

	// A unique identifier for the ensuing upload operation
	UploadId string `json:"upload_id"`

	// The required size (in bytes) that the file must be segmented into for each chunk
	ChunkSize int64 `json:"chunk_size"`
}

type UploadBeginRequestFile struct {

	// The algorithm used to compress the file. Valid values: br,gzip,deflate,none
	Compression string `json:"Compression,omitempty"`

	Hash Hash `json:"hash,omitempty"`

	// Name of the file including the extension, without the directory
	Name string `json:"name"`

	// MIME type of the file
	MimeType string `json:"mime_type"`

	// Size of the file contents, in bytes
	Size int64 `json:"size"`
}

// Hash - Checksums on the file contents
type Hash struct {

	// SHA256 of the contents
	Sha256 string `json:"sha256,omitempty"`
}

// =============================================================================
// ================================== Upload Complete ==========================
// =============================================================================

// UploadCompleteRequest - Request to verify and finish an uploaded file
type UploadCompleteRequest struct {
	Transithash UploadCompleteRequestTransithash `json:"transithash"`
}

type UploadComplete200Response struct {
	Status string `json:"status,omitempty"`
}

// UploadCompleteRequestTransithash - the transithash (sha256 of the concatenation of each in-order chunk hash) of the entire file contents
type UploadCompleteRequestTransithash struct {

	// SHA256 hash
	Sha256 string `json:"sha256"`
}

// =============================================================================
// ================================== Errors ===================================
// =============================================================================

// HTTPError is the HTTP error to be returned to the client.
// If no StatusCode is defined, http.StatusInternalServerError will be used by
// String() and Error().
type HTTPError struct {

	// The HTTP status code of the error.
	StatusCode int `json:"statusCode"`

	// Error is the Status Code as text.
	Status string `json:"error"`

	// (optional) Error message.
	Message string `json:"message,omitempty"`
}

func (e HTTPError) Error() string {
	return e.String()
}

func (e HTTPError) String() string {
	statusCode := e.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusInternalServerError
	}

	status := e.Status
	if status == "" {
		status = http.StatusText(statusCode)
	}

	return fmt.Sprintf("%d - %s: %s", statusCode, status, e.Message)
}

func (e HTTPError) MarshalJSON() ([]byte, error) {
	statusCode := e.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusInternalServerError
	}

	status := e.Status
	if status == "" {
		status = http.StatusText(statusCode)
	}

	type tmp HTTPError
	return json.Marshal(tmp(HTTPError{
		StatusCode: statusCode,
		Status:     status,
		Message:    e.Message,
	}))
}
