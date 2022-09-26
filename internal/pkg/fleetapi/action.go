// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

const (
	// ActionTypeUnknown is used to indicate that the elastic-agent does not know how to handle the action
	ActionTypeUnknown = "UNKNOWN"
	// ActionTypeUpgrade specifies upgrade action.
	ActionTypeUpgrade = "UPGRADE"
	// ActionTypeUnenroll specifies unenroll action.
	ActionTypeUnenroll = "UNENROLL"
	// ActionTypePolicyChange specifies policy change action.
	ActionTypePolicyChange = "POLICY_CHANGE"
	// ActionTypePolicyReassign specifies policy reassign action.
	ActionTypePolicyReassign = "POLICY_REASSIGN"
	// ActionTypeSettings specifies change of agent settings.
	ActionTypeSettings = "SETTINGS"
	// ActionTypeInputAction specifies agent action.
	ActionTypeInputAction = "INPUT_ACTION"
	// ActionTypeCancel specifies a cancel action.
	ActionTypeCancel = "CANCEL"
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
	// StartTime returns the earliest time an action should start (for schduled actions)
	// Only ActionUpgrade implements this at the moment
	StartTime() (time.Time, error)
	// Expiration returns the time where an action is expired and should not be ran (for scheduled actions)
	// Only ActionUpgrade implements this at the moment
	Expiration() (time.Time, error)
}

// FleetAction represents an action from fleet-server.
// should copy the action definition in fleet-server/model/schema.json
type FleetAction struct {
	ActionID         string          `yaml:"action_id" json:"id"` // NOTE schema defines this as action_id, but fleet-server remaps it to id in the json response to agent check-in.
	ActionType       string          `yaml:"type,omitempty" json:"type,omitempty"`
	InputType        string          `yaml:"input_type,omitempty" json:"input_type,omitempty"`
	ActionExpiration string          `yaml:"expiration,omitempty" json:"expiration,omitempty"`
	ActionStartTime  string          `yaml:"start_time,omitempty" json:"start_time,omitempty"`
	Timeout          int64           `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Data             json.RawMessage `yaml:"data,omitempty" json:"data,omitempty"`
	//Agents []string // disabled, fleet-server uses this to generate each agent's actions
	//Timestamp string // disabled, agent does not care when the document was created
	//UserID string // disabled, agent does not care
	//MinimumExecutionDuration int64 // disabled, used by fleet-server for scheduling
}

// ActionUnknown is an action that is not know by the current version of the Agent and we don't want
// to return an error at parsing time but at execution time we can report or ignore.
//
// NOTE: We only keep the original type and the action id, the payload of the event is dropped, we
// do this to make sure we do not leak any unwanted information.
type ActionUnknown struct {
	originalType string
	ActionID     string
	ActionType   string
}

// Type returns the type of the Action.
func (a *ActionUnknown) Type() string {
	return ActionTypeUnknown
}

// ID returns the ID of the Action.
func (a *ActionUnknown) ID() string {
	return a.ActionID
}

// StartTime returns ErrNoStartTime
func (a *ActionUnknown) StartTime() (time.Time, error) {
	return time.Time{}, ErrNoStartTime
}

// Expiration returns ErrNoExpiration
func (a *ActionUnknown) Expiration() (time.Time, error) {
	return time.Time{}, ErrNoExpiration
}

func (a *ActionUnknown) String() string {
	var s strings.Builder
	s.WriteString("action_id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	s.WriteString(" (original type: ")
	s.WriteString(a.OriginalType())
	s.WriteString(")")
	return s.String()
}

// OriginalType returns the original type of the action as returned by the API.
func (a *ActionUnknown) OriginalType() string {
	return a.originalType
}

// ActionPolicyReassign is a request to apply a new
type ActionPolicyReassign struct {
	ActionID   string `yaml:"action_id"`
	ActionType string `yaml:"type"`
}

func (a *ActionPolicyReassign) String() string {
	var s strings.Builder
	s.WriteString("action_id: ")
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

// StartTime returns ErrNoStartTime
func (a *ActionPolicyReassign) StartTime() (time.Time, error) {
	return time.Time{}, ErrNoStartTime
}

// Expiration returns ErrNoExpiration
func (a *ActionPolicyReassign) Expiration() (time.Time, error) {
	return time.Time{}, ErrNoExpiration
}

// ActionPolicyChange is a request to apply a new
type ActionPolicyChange struct {
	ActionID   string                 `yaml:"action_id"`
	ActionType string                 `yaml:"type"`
	Policy     map[string]interface{} `json:"policy" yaml:"policy,omitempty"`
}

func (a *ActionPolicyChange) String() string {
	var s strings.Builder
	s.WriteString("action_id: ")
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

// StartTime returns ErrNoStartTime
func (a *ActionPolicyChange) StartTime() (time.Time, error) {
	return time.Time{}, ErrNoStartTime
}

// Expiration returns ErrNoExpiration
func (a *ActionPolicyChange) Expiration() (time.Time, error) {
	return time.Time{}, ErrNoExpiration
}

// ActionUpgrade is a request for agent to upgrade.
type ActionUpgrade struct {
	ActionID         string `yaml:"action_id"`
	ActionType       string `yaml:"type"`
	ActionStartTime  string `json:"start_time" yaml:"start_time,omitempty"` // TODO change to time.Time in unmarshal
	ActionExpiration string `json:"expiration" yaml:"expiration,omitempty"`
	Version          string `json:"version" yaml:"version,omitempty"`
	SourceURI        string `json:"source_uri,omitempty" yaml:"source_uri,omitempty"`
}

func (a *ActionUpgrade) String() string {
	var s strings.Builder
	s.WriteString("action_id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	return s.String()
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

// ActionUnenroll is a request for agent to unhook from fleet.
type ActionUnenroll struct {
	ActionID   string `yaml:"action_id"`
	ActionType string `yaml:"type"`
	IsDetected bool   `json:"is_detected,omitempty" yaml:"is_detected,omitempty"`
}

func (a *ActionUnenroll) String() string {
	var s strings.Builder
	s.WriteString("action_id: ")
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

// StartTime returns ErrNoStartTime
func (a *ActionUnenroll) StartTime() (time.Time, error) {
	return time.Time{}, ErrNoStartTime
}

// Expiration returns ErrNoExpiration
func (a *ActionUnenroll) Expiration() (time.Time, error) {
	return time.Time{}, ErrNoExpiration
}

// ActionSettings is a request to change agent settings.
type ActionSettings struct {
	ActionID   string `yaml:"action_id"`
	ActionType string `yaml:"type"`
	LogLevel   string `json:"log_level" yaml:"log_level,omitempty"`
}

// ID returns the ID of the Action.
func (a *ActionSettings) ID() string {
	return a.ActionID
}

// Type returns the type of the Action.
func (a *ActionSettings) Type() string {
	return a.ActionType
}

// StartTime returns ErrNoStartTime
func (a *ActionSettings) StartTime() (time.Time, error) {
	return time.Time{}, ErrNoStartTime
}

// Expiration returns ErrNoExpiration
func (a *ActionSettings) Expiration() (time.Time, error) {
	return time.Time{}, ErrNoExpiration
}

func (a *ActionSettings) String() string {
	var s strings.Builder
	s.WriteString("action_id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	s.WriteString(", log_level: ")
	s.WriteString(a.LogLevel)
	return s.String()
}

// ActionCancel is a request to cancel an action.
type ActionCancel struct {
	ActionID   string `yaml:"action_id"`
	ActionType string `yaml:"type"`
	TargetID   string `json:"target_id" yaml:"target_id,omitempty"`
}

// ID returns the ID of the Action.
func (a *ActionCancel) ID() string {
	return a.ActionID
}

// Type returns the type of the Action.
func (a *ActionCancel) Type() string {
	return a.ActionType
}

// StartTime returns ErrNoStartTime
func (a *ActionCancel) StartTime() (time.Time, error) {
	return time.Time{}, ErrNoStartTime
}

// Expiration returns ErrNoExpiration
func (a *ActionCancel) Expiration() (time.Time, error) {
	return time.Time{}, ErrNoExpiration
}

func (a *ActionCancel) String() string {
	var s strings.Builder
	s.WriteString("action_id: ")
	s.WriteString(a.ActionID)
	s.WriteString(", type: ")
	s.WriteString(a.ActionType)
	s.WriteString(", target_id: ")
	s.WriteString(a.TargetID)
	return s.String()
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
	Error       string                 `json:"error,omitempty" mapstructure:"error,omitempty"`
}

func (a *ActionApp) String() string {
	var s strings.Builder
	s.WriteString("action_id: ")
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

// StartTime returns ErrNoStartTime
func (a *ActionApp) StartTime() (time.Time, error) {
	return time.Time{}, ErrNoStartTime
}

// Expiration returns ErrExpiration
func (a *ActionApp) Expiration() (time.Time, error) {
	return time.Time{}, ErrNoExpiration
}

// MarshalMap marshals ActionApp into a corresponding map
func (a *ActionApp) MarshalMap() (map[string]interface{}, error) {
	var res map[string]interface{}
	err := mapstructure.Decode(a, &res)
	return res, err
}

// Actions is a list of Actions to executes and allow to unmarshal heterogenous action type.
type Actions []Action

// UnmarshalJSON takes every raw representation of an action and try to decode them.
func (a *Actions) UnmarshalJSON(data []byte) error {
	var responses []FleetAction
	if err := json.Unmarshal(data, &responses); err != nil {
		return errors.New(err,
			"fail to decode actions",
			errors.TypeConfig)
	}

	actions := make([]Action, 0, len(responses))
	for _, response := range responses {
		var action Action
		switch response.ActionType {
		case ActionTypePolicyChange:
			action = &ActionPolicyChange{
				ActionID:   response.ActionID,
				ActionType: response.ActionType,
			}
			if err := json.Unmarshal(response.Data, action); err != nil {
				return errors.New(err,
					"fail to decode POLICY_CHANGE action",
					errors.TypeConfig)
			}
		case ActionTypePolicyReassign:
			action = &ActionPolicyReassign{
				ActionID:   response.ActionID,
				ActionType: response.ActionType,
			}
		case ActionTypeInputAction:
			action = &ActionApp{
				ActionID:   response.ActionID,
				ActionType: response.ActionType,
				InputType:  response.InputType,
				Timeout:    response.Timeout,
				Data:       response.Data,
			}
		case ActionTypeUnenroll:
			action = &ActionUnenroll{
				ActionID:   response.ActionID,
				ActionType: response.ActionType,
			}
		case ActionTypeUpgrade:
			action = &ActionUpgrade{
				ActionID:         response.ActionID,
				ActionType:       response.ActionType,
				ActionStartTime:  response.ActionStartTime,
				ActionExpiration: response.ActionExpiration,
			}

			if err := json.Unmarshal(response.Data, action); err != nil {
				return errors.New(err,
					"fail to decode UPGRADE_ACTION action",
					errors.TypeConfig)
			}
		case ActionTypeSettings:
			action = &ActionSettings{
				ActionID:   response.ActionID,
				ActionType: response.ActionType,
			}

			if err := json.Unmarshal(response.Data, action); err != nil {
				return errors.New(err,
					"fail to decode SETTINGS_ACTION action",
					errors.TypeConfig)
			}
		case ActionTypeCancel:
			action = &ActionCancel{
				ActionID:   response.ActionID,
				ActionType: response.ActionType,
			}
			if err := json.Unmarshal(response.Data, action); err != nil {
				return errors.New(err,
					"fail to decode CANCEL_ACTION action",
					errors.TypeConfig)
			}
		default:
			action = &ActionUnknown{
				ActionID:     response.ActionID,
				ActionType:   ActionTypeUnknown,
				originalType: response.ActionType,
			}
		}
		actions = append(actions, action)
	}

	*a = actions
	return nil
}

// UnmarshalYAML attempts to decode yaml actions.
func (a *Actions) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var nodes []FleetAction
	if err := unmarshal(&nodes); err != nil {
		return errors.New(err,
			"fail to decode action",
			errors.TypeConfig)
	}
	actions := make([]Action, 0, len(nodes))
	for i := range nodes {
		var action Action
		n := nodes[i]
		switch n.ActionType {
		case ActionTypePolicyChange:
			action = &ActionPolicyChange{
				ActionID:   n.ActionID,
				ActionType: n.ActionType,
			}
			if err := yaml.Unmarshal(n.Data, action); err != nil {
				return errors.New(err,
					"fail to decode POLICY_CHANGE action",
					errors.TypeConfig)
			}
		case ActionTypePolicyReassign:
			action = &ActionPolicyReassign{
				ActionID:   n.ActionID,
				ActionType: n.ActionType,
			}
		case ActionTypeInputAction:
			action = &ActionApp{
				ActionID:   n.ActionID,
				ActionType: n.ActionType,
				InputType:  n.InputType,
				Timeout:    n.Timeout,
				Data:       n.Data,
			}
		case ActionTypeUnenroll:
			action = &ActionUnenroll{
				ActionID:   n.ActionID,
				ActionType: n.ActionType,
			}
		case ActionTypeUpgrade:
			action = &ActionUpgrade{
				ActionID:         n.ActionID,
				ActionType:       n.ActionType,
				ActionStartTime:  n.ActionStartTime,
				ActionExpiration: n.ActionExpiration,
			}
			if err := yaml.Unmarshal(n.Data, &action); err != nil {
				return errors.New(err,
					"fail to decode UPGRADE_ACTION action",
					errors.TypeConfig)
			}
		case ActionTypeSettings:
			action = &ActionSettings{
				ActionID:   n.ActionID,
				ActionType: n.ActionType,
			}
			if err := yaml.Unmarshal(n.Data, action); err != nil {
				return errors.New(err,
					"fail to decode SETTINGS_ACTION action",
					errors.TypeConfig)
			}
		case ActionTypeCancel:
			action = &ActionCancel{
				ActionID:   n.ActionID,
				ActionType: n.ActionType,
			}
			if err := yaml.Unmarshal(n.Data, action); err != nil {
				return errors.New(err,
					"fail to decode CANCEL_ACTION action",
					errors.TypeConfig)
			}
		default:
			action = &ActionUnknown{
				ActionID:     n.ActionID,
				ActionType:   ActionTypeUnknown,
				originalType: n.ActionType,
			}
		}
		actions = append(actions, action)
	}
	*a = actions
	return nil
}
