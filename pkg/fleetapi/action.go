// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"

	api "github.com/elastic/fleet-server/pkg/api"
)

const (
	// ActionTypeUnknown is a client-side catch-all for unrecognized action types (not in Fleet Server spec).
	ActionTypeUnknown        = "UNKNOWN"
	ActionTypeUpgrade        = string(api.UPGRADE)
	ActionTypeUnenroll       = string(api.UNENROLL)
	ActionTypePolicyChange   = string(api.POLICYCHANGE)
	ActionTypePolicyReassign = string(api.POLICYREASSIGN)
	ActionTypeSettings       = string(api.SETTINGS)
	ActionTypeInputAction    = string(api.INPUTACTION)
	ActionTypeCancel         = string(api.CANCEL)
	ActionTypeDiagnostics    = string(api.REQUESTDIAGNOSTICS)
)

// Error values that the Action interface can return
var (
	ErrNoStartTime  = fmt.Errorf("action has no start time")
	ErrNoExpiration = fmt.Errorf("action has no expiration")
)

// Action base interface for all the implemented action from the fleet API.
type Action interface {
	fmt.Stringer
	Type() string
	ID() string
	// AckEvent builds the ack event for this action, to be sent to fleet-server as part of an
	// AckRequest. agentID and ts are injected here (rather than set on the returned value) because
	// api.AckRequest_Events_Item is an opaque union type with no settable fields after construction.
	AckEvent(agentID string, ts time.Time) api.AckRequest_Events_Item
}

// Actions is a slice of Actions to executes and allow to unmarshal
// heterogeneous action types.
type Actions []Action

// ScheduledAction is an Action that may be executed at a later date
// Only ActionUpgrade implements this at the moment
type ScheduledAction interface {
	Action
	// StartTime returns the earliest time an action should start.
	StartTime() (time.Time, error)
	// Expiration returns the time where an action is expired and should not be ran.
	Expiration() (time.Time, error)
}

// RetryableAction is an Action that may be scheduled for a retry.
type RetryableAction interface {
	ScheduledAction
	// RetryAttempt returns the retry-attempt number of the action
	// the retry_attempt number is meant to be an internal counter for the elastic-agent and not communicated to fleet-server or ES.
	// If RetryAttempt returns > 1, and GetError is not nil the acker should signal that the action is being retried.
	// If RetryAttempt returns < 1, and GetError is not nil the acker should signal that the action has failed.
	RetryAttempt() int
	// SetRetryAttempt sets the retry-attempt number of the action
	// the retry_attempt number is meant to be an internal counter for the elastic-agent and not communicated to fleet-server or ES.
	SetRetryAttempt(int)
	// SetStartTime sets the start_time of the action to the specified value.
	// this is used by the action-retry mechanism.
	SetStartTime(t time.Time)
	// GetError returns the error that is associated with the retry.
	// If it is a retryable action fleet-server should mark it as such.
	// Otherwise, fleet-server should mark the action as failed.
	GetError() error
	// SetError sets the retryable action error
	SetError(error)
}

type Signed struct {
	Data      string `json:"data" yaml:"data" mapstructure:"data"`
	Signature string `json:"signature" yaml:"signature"  mapstructure:"signature"`
}

// NewAction returns a new, zero-value, action of the type defined by 'actionType'
// or an ActionUnknown with the 'OriginalType' field set to 'actionType' if the
// type is not valid.
func NewAction(actionType string) Action {
	var action Action

	// keep the case statements alphabetically sorted
	switch actionType {
	case ActionTypeCancel:
		action = &ActionCancel{}
	case ActionTypeDiagnostics:
		action = &ActionDiagnostics{}
	case ActionTypeInputAction:
		action = &ActionApp{}
	case ActionTypePolicyChange:
		action = &ActionPolicyChange{}
	case ActionTypePolicyReassign:
		action = &ActionPolicyReassign{}
	case ActionTypeSettings:
		action = &ActionSettings{}
	case ActionTypeUnenroll:
		action = &ActionUnenroll{}
	case ActionTypeUpgrade:
		action = &ActionUpgrade{}
	default:
		action = &ActionUnknown{OriginalType: actionType}
	}

	return action
}

// newGenericEvent builds the common fields shared by every ack event.
func newGenericEvent(id, aType, agentID string, ts time.Time) api.GenericEvent {
	return api.GenericEvent{
		Type:      api.ACTIONRESULT,
		Subtype:   api.EventSubtypeACKNOWLEDGED,
		ActionId:  id,
		AgentId:   agentID,
		Timestamp: ts,
		Message:   fmt.Sprintf("Action %q of type %q acknowledged.", id, aType),
	}
}

// toGenericAckEvent wraps a GenericEvent in the AckRequest_Events_Item union.
func toGenericAckEvent(ev api.GenericEvent) api.AckRequest_Events_Item {
	var item api.AckRequest_Events_Item
	_ = item.FromGenericEvent(ev)
	return item
}

// newAckEvent builds the default (no-error) ack event for actions with no additional fields to report.
func newAckEvent(id, aType, agentID string, ts time.Time) api.AckRequest_Events_Item {
	return toGenericAckEvent(newGenericEvent(id, aType, agentID, ts))
}

// ActionUnknown is an action that is not know by the current version of the Agent and we don't want
// to return an error at parsing time but at execution time we can report or ignore.
//
// NOTE: We only keep the original type and the action id, the payload of the event is dropped, we
// do this to make sure we do not leak any unwanted information.
type ActionUnknown struct {
	ActionID   string `json:"id" yaml:"id" mapstructure:"id"`
	ActionType string `json:"type,omitempty" yaml:"type,omitempty" mapstructure:"type"`
	// OriginalType is the original type of the action as returned by the API.
	OriginalType string `json:"original_type,omitempty" yaml:"original_type,omitempty" mapstructure:"original_type"`
}

// Type returns the type of the Action.
func (a *ActionUnknown) Type() string {
	return ActionTypeUnknown
}

// ID returns the ID of the Action.
func (a *ActionUnknown) ID() string {
	return a.ActionID
}

func (a *ActionUnknown) String() string {
	var s strings.Builder
	s.WriteString("id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	s.WriteString(" (original type: ")
	s.WriteString(a.OriginalType)
	s.WriteString(")")
	return s.String()
}

func (a *ActionUnknown) AckEvent(agentID string, ts time.Time) api.AckRequest_Events_Item {
	event := newGenericEvent(a.ActionID, a.ActionType, agentID, ts)
	errStr := fmt.Sprintf("Action %q of type %q is unknown to the elastic-agent", a.ActionID, a.OriginalType)
	event.Error = &errStr
	return toGenericAckEvent(event)
}

// ActionPolicyReassign is a request to apply a new policy
type ActionPolicyReassign struct {
	ActionID   string                   `json:"id" yaml:"id"`
	ActionType string                   `json:"type" yaml:"type"`
	Data       ActionPolicyReassignData `json:"data,omitempty"`
}

type ActionPolicyReassignData struct {
	PolicyID string `json:"policy_id"`
}

func (a *ActionPolicyReassign) String() string {
	var s strings.Builder
	s.WriteString("id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	return s.String()
}

// Type returns the type of the Action.
func (a *ActionPolicyReassign) Type() string {
	return a.ActionType
}

// ID returns the ID of the Action.
func (a *ActionPolicyReassign) ID() string {
	return a.ActionID
}

func (a *ActionPolicyReassign) AckEvent(agentID string, ts time.Time) api.AckRequest_Events_Item {
	return newAckEvent(a.ActionID, a.ActionType, agentID, ts)
}

// ActionPolicyChange is a request to apply a new
type ActionPolicyChange struct {
	ActionID   string                 `json:"id" yaml:"id"`
	ActionType string                 `json:"type" yaml:"type"`
	Data       ActionPolicyChangeData `json:"data,omitempty" yaml:"data,omitempty"`
}

type ActionPolicyChangeData struct {
	Policy map[string]interface{} `json:"policy" yaml:"policy,omitempty"`
}

func (a *ActionPolicyChange) String() string {
	var s strings.Builder
	s.WriteString("id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	return s.String()
}

// Type returns the type of the Action.
func (a *ActionPolicyChange) Type() string {
	return a.ActionType
}

// ID returns the ID of the Action.
func (a *ActionPolicyChange) ID() string {
	return a.ActionID
}

func (a *ActionPolicyChange) AckEvent(agentID string, ts time.Time) api.AckRequest_Events_Item {
	return newAckEvent(a.ActionID, a.ActionType, agentID, ts)
}

// ActionUpgrade is a request for agent to upgrade.
type ActionUpgrade struct {
	ActionID         string `json:"id" yaml:"id" mapstructure:"id"`
	ActionType       string `json:"type" yaml:"type" mapstructure:"type"`
	ActionStartTime  string `json:"start_time" yaml:"start_time,omitempty" mapstructure:"-"` // TODO change to time.Time in unmarshal
	ActionExpiration string `json:"expiration" yaml:"expiration,omitempty" mapstructure:"-"`
	// does anyone know why those aren't mapped to mapstructure?
	Data   ActionUpgradeData `json:"data,omitempty" mapstructure:"-"`
	Signed *Signed           `json:"signed,omitempty" yaml:"signed,omitempty" mapstructure:"signed,omitempty"`
	Err    error             `json:"-" yaml:"-" mapstructure:"-"`
}

type ActionUpgradeData struct {
	Version   string `json:"version" yaml:"version,omitempty" mapstructure:"-"`
	SourceURI string `json:"source_uri,omitempty" yaml:"source_uri,omitempty" mapstructure:"-"`
	// TODO: update fleet open api schema
	Retry int `json:"retry_attempt,omitempty" yaml:"retry_attempt,omitempty" mapstructure:"-"`
}

func (a *ActionUpgrade) String() string {
	var s strings.Builder
	s.WriteString("id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	return s.String()
}

func (a *ActionUpgrade) AckEvent(agentID string, ts time.Time) api.AckRequest_Events_Item {
	event := api.UpgradeEvent{
		Type:      api.ACTIONRESULT,
		Subtype:   api.EventSubtypeACKNOWLEDGED,
		ActionId:  a.ActionID,
		AgentId:   agentID,
		Timestamp: ts,
		Message:   fmt.Sprintf("Action %q of type %q acknowledged.", a.ActionID, a.ActionType),
	}
	if a.Err != nil {
		// FIXME Do we want to change EventType/SubType here?
		errStr := a.Err.Error()
		event.Error = &errStr
		// retry is set to -1 if it will not re attempt
		event.Payload = &struct {
			Retry        bool `json:"retry"`
			RetryAttempt int  `json:"retry_attempt"`
		}{
			Retry:        a.Data.Retry >= 1,
			RetryAttempt: a.Data.Retry,
		}
	}
	var item api.AckRequest_Events_Item
	_ = item.FromUpgradeEvent(event)
	return item
}

// Type returns the type of the Action.
func (a *ActionUpgrade) Type() string {
	return a.ActionType
}

// ID returns the ID of the Action.
func (a *ActionUpgrade) ID() string {
	return a.ActionID
}

// StartTime returns the start_time as a UTC time.Time or ErrNoStartTime if there is no start time
func (a *ActionUpgrade) StartTime() (time.Time, error) {
	if a.ActionStartTime == "" {
		return time.Time{}, ErrNoStartTime
	}
	ts, err := time.Parse(time.RFC3339, a.ActionStartTime)
	if err != nil {
		return time.Time{}, err
	}
	return ts.UTC(), nil
}

// Expiration returns the expiration as a UTC time.Time or ErrExpiration if there is no expiration
func (a *ActionUpgrade) Expiration() (time.Time, error) {
	if a.ActionExpiration == "" {
		return time.Time{}, ErrNoExpiration
	}
	ts, err := time.Parse(time.RFC3339, a.ActionExpiration)
	if err != nil {
		return time.Time{}, err
	}
	return ts.UTC(), nil
}

// RetryAttempt will return the retry_attempt of the action
func (a *ActionUpgrade) RetryAttempt() int {
	return a.Data.Retry
}

// SetRetryAttempt sets the retry_attempt of the action
func (a *ActionUpgrade) SetRetryAttempt(n int) {
	a.Data.Retry = n
}

// GetError returns the error associated with the attempt to run the action.
func (a *ActionUpgrade) GetError() error {
	return a.Err
}

// SetError sets the error associated with the attempt to run the action.
func (a *ActionUpgrade) SetError(err error) {
	a.Err = err
}

// SetStartTime sets the start time of the action.
func (a *ActionUpgrade) SetStartTime(t time.Time) {
	a.ActionStartTime = t.Format(time.RFC3339)
}

// MarshalMap marshals ActionUpgrade into a corresponding map
func (a *ActionUpgrade) MarshalMap() (map[string]interface{}, error) {
	var res map[string]interface{}
	err := mapstructure.Decode(a, &res)
	return res, err
}

// ActionUnenroll is a request for agent to unhook from fleet.
type ActionUnenroll struct {
	ActionID   string  `json:"id" yaml:"id" mapstructure:"id"`
	ActionType string  `json:"type" yaml:"type" mapstructure:"type"`
	IsDetected bool    `json:"is_detected,omitempty" yaml:"is_detected,omitempty" mapstructure:"-"`
	Signed     *Signed `json:"signed,omitempty" mapstructure:"signed,omitempty"`
}

func (a *ActionUnenroll) String() string {
	var s strings.Builder
	s.WriteString("id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	return s.String()
}

// Type returns the type of the Action.
func (a *ActionUnenroll) Type() string {
	return a.ActionType
}

// ID returns the ID of the Action.
func (a *ActionUnenroll) ID() string {
	return a.ActionID
}

func (a *ActionUnenroll) AckEvent(agentID string, ts time.Time) api.AckRequest_Events_Item {
	return newAckEvent(a.ActionID, a.ActionType, agentID, ts)
}

// MarshalMap marshals ActionUnenroll into a corresponding map
func (a *ActionUnenroll) MarshalMap() (map[string]interface{}, error) {
	var res map[string]interface{}
	err := mapstructure.Decode(a, &res)
	return res, err
}

// ActionSettings is a request to change agent settings.
type ActionSettings struct {
	ActionID   string             `json:"id" yaml:"id"`
	ActionType string             `json:"type" yaml:"type"`
	Data       ActionSettingsData `json:"data,omitempty"`
}

type ActionSettingsData struct {
	// LogLevel can only be one of "debug", "info", "warning", "error"
	// TODO: add validation
	LogLevel string `json:"log_level" yaml:"log_level,omitempty"`
}

// ID returns the ID of the Action.
func (a *ActionSettings) ID() string {
	return a.ActionID
}

// Type returns the type of the Action.
func (a *ActionSettings) Type() string {
	return a.ActionType
}

func (a *ActionSettings) String() string {
	var s strings.Builder
	s.WriteString("id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	s.WriteString(", log_level: ")
	s.WriteString(a.Data.LogLevel)
	return s.String()
}

func (a *ActionSettings) AckEvent(agentID string, ts time.Time) api.AckRequest_Events_Item {
	return newAckEvent(a.ActionID, a.ActionType, agentID, ts)
}

// ActionCancel is a request to cancel an action.
type ActionCancel struct {
	ActionID   string           `json:"id" yaml:"id"`
	ActionType string           `json:"type" yaml:"type"`
	Data       ActionCancelData `json:"data,omitempty"`
}

type ActionCancelData struct {
	TargetID string `json:"target_id" yaml:"target_id,omitempty"`
}

// ID returns the ID of the Action.
func (a *ActionCancel) ID() string {
	return a.ActionID
}

// Type returns the type of the Action.
func (a *ActionCancel) Type() string {
	return a.ActionType
}

func (a *ActionCancel) String() string {
	var s strings.Builder
	s.WriteString("id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	s.WriteString(", target_id: ")
	s.WriteString(a.Data.TargetID)
	return s.String()
}

func (a *ActionCancel) AckEvent(agentID string, ts time.Time) api.AckRequest_Events_Item {
	return newAckEvent(a.ActionID, a.ActionType, agentID, ts)
}

// ActionDiagnostics is a request to gather and upload a diagnostics bundle.
type ActionDiagnostics struct {
	ActionID   string                `json:"id"`
	ActionType string                `json:"type"`
	Data       ActionDiagnosticsData `json:"data"`
	UploadID   string                `json:"-"`
	Err        error                 `json:"-"`
}

type ActionDiagnosticsData struct {
	AdditionalMetrics []string `json:"additional_metrics"`
	ExcludeEventsLog  bool     `json:"exclude_events_log"`
}

// ID returns the ID of the action.
func (a *ActionDiagnostics) ID() string {
	return a.ActionID
}

// Type returns the type of the action.
func (a *ActionDiagnostics) Type() string {
	return a.ActionType
}

func (a *ActionDiagnostics) String() string {
	var s strings.Builder
	s.WriteString("id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	return s.String()
}

func (a *ActionDiagnostics) AckEvent(agentID string, ts time.Time) api.AckRequest_Events_Item {
	event := api.DiagnosticsEvent{
		Type:      api.ACTIONRESULT,
		Subtype:   api.EventSubtypeACKNOWLEDGED,
		ActionId:  a.ActionID,
		AgentId:   agentID,
		Timestamp: ts,
		Message:   fmt.Sprintf("Action %q of type %q acknowledged.", a.ActionID, a.ActionType),
	}
	if a.Err != nil {
		errStr := a.Err.Error()
		event.Error = &errStr
	}
	if a.UploadID != "" {
		event.Data = &struct {
			UploadId string `json:"upload_id"`
		}{UploadId: a.UploadID}
	}

	var item api.AckRequest_Events_Item
	_ = item.FromDiagnosticsEvent(event)
	return item
}

// ActionApp is the application action request.
type ActionApp struct {
	ActionID    string                 `json:"id" mapstructure:"id"`
	ActionType  string                 `json:"type" mapstructure:"type"`
	InputType   string                 `json:"input_type" mapstructure:"input_type"`
	Timeout     int64                  `json:"timeout,omitempty" mapstructure:"timeout,omitempty"`
	Data        json.RawMessage        `json:"data" mapstructure:"data"`
	Response    map[string]interface{} `json:"response,omitempty" mapstructure:"response,omitempty"`
	StartedAt   string                 `json:"started_at,omitempty" mapstructure:"started_at,omitempty"`
	CompletedAt string                 `json:"completed_at,omitempty" mapstructure:"completed_at,omitempty"`
	Signed      *Signed                `json:"signed,omitempty" mapstructure:"signed,omitempty"`
	Error       string                 `json:"error,omitempty" mapstructure:"error,omitempty"`
}

func (a *ActionApp) String() string {
	var s strings.Builder
	s.WriteString("id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	s.WriteString(", input_type: ")
	s.WriteString(a.InputType)
	return s.String()
}

// ID returns the ID of the Action.
func (a *ActionApp) ID() string {
	return a.ActionID
}

// Type returns the type of the Action.
func (a *ActionApp) Type() string {
	return a.ActionType
}

func (a *ActionApp) AckEvent(agentID string, ts time.Time) api.AckRequest_Events_Item {
	event := api.InputEvent{
		Type:            api.ACTIONRESULT,
		Subtype:         api.EventSubtypeACKNOWLEDGED,
		ActionId:        a.ActionID,
		AgentId:         agentID,
		Timestamp:       ts,
		Message:         fmt.Sprintf("Action %q of type %q acknowledged.", a.ActionID, a.ActionType),
		ActionInputType: a.InputType,
		ActionData:      a.Data,
		// StartedAt/CompletedAt fall back to ts if a.StartedAt/a.CompletedAt are
		// empty or fail to parse, so the event never carries a zero time.Time.
		StartedAt:   ts,
		CompletedAt: ts,
	}
	if a.Response != nil {
		if b, err := json.Marshal(a.Response); err == nil {
			event.ActionResponse = b
		}
	}
	if t, err := time.Parse(time.RFC3339Nano, a.StartedAt); err == nil {
		event.StartedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, a.CompletedAt); err == nil {
		event.CompletedAt = t
	}
	if a.Error != "" {
		errStr := a.Error
		event.Error = &errStr
	}

	var item api.AckRequest_Events_Item
	_ = item.FromInputEvent(event)
	return item
}

// MarshalMap marshals ActionApp into a corresponding map
func (a *ActionApp) MarshalMap() (map[string]interface{}, error) {
	var res map[string]interface{}
	err := mapstructure.Decode(a, &res)
	return res, err
}

// UnmarshalJSON takes every raw representation of an action and try to decode them.
func (a *Actions) UnmarshalJSON(data []byte) error {
	var typeUnmarshaler []struct {
		ActionType string `json:"type,omitempty" yaml:"type,omitempty"`
	}

	if err := json.Unmarshal(data, &typeUnmarshaler); err != nil {
		return fmt.Errorf("fail to decode actions to read their types: %w", err)
	}

	rawActions := make([]json.RawMessage, len(typeUnmarshaler))
	if err := json.Unmarshal(data, &rawActions); err != nil {
		return fmt.Errorf("fail to decode actions: %w", err)
	}

	actions := make([]Action, 0, len(typeUnmarshaler))
	for i, response := range typeUnmarshaler {
		action := NewAction(response.ActionType)

		if err := json.Unmarshal(rawActions[i], action); err != nil {
			return fmt.Errorf("fail to decode %s action: %w", action.Type(), err)
		}
		actions = append(actions, action)
	}

	*a = actions
	return nil
}

// UnmarshalYAML prevents to unmarshal actions from YAML.
func (a *Actions) UnmarshalYAML(_ func(interface{}) error) error {
	return errors.New("Actions cannot be Unmarshalled from YAML")
}

// MarshalYAML prevents to marshal actions from YAML.
func (a *Actions) MarshalYAML() (interface{}, error) {
	return nil, errors.New("Actions cannot be Marshaled into YAML")
}
