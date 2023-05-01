// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator/state"
	"github.com/elastic/elastic-agent/internal/pkg/agent/protection"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	defaultActionTimeout = time.Minute
	maxActionTimeout     = time.Hour
)

var errActionTimeoutInvalid = errors.New("action timeout is invalid")

// Interface to coordinatitor for AppAction handler testability
type ActionProtectionCoordinator interface {
	Protection() protection.Config
	State() state.State
	PerformAction(ctx context.Context, comp component.Component, unit component.Unit, name string, params map[string]interface{}) (map[string]interface{}, error)
}

// AppAction is a handler for application actions.
type AppAction struct {
	log     *logger.Logger
	coord   ActionProtectionCoordinator
	agentID string
}

// NewAppAction creates a new AppAction handler.
func NewAppAction(log *logger.Logger, coord ActionProtectionCoordinator, agentID string) *AppAction {
	return &AppAction{
		log:     log,
		coord:   coord,
		agentID: agentID,
	}
}

// Handle handles application action.
func (h *AppAction) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Debugf("handlerAppAction: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionApp)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionApp and received %T", a)
	}

	// Validate action
	h.log.Debugf("handlerAppAction: validate action '%+v', for agentID %s", a, h.agentID)
	validated, err := protection.ValidateAction(*action, h.coord.Protection().SignatureValidationKey, h.agentID)
	if err != nil {
		action.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
		action.CompletedAt = action.StartedAt
		h.log.Errorf("handlerAppAction: action '%+v' failed validation: %v", action, err) // error details are logged
		action.Error = fmt.Sprintf("action failed validation: %s", action.InputType)      // generic error message for the action response
		return acker.Ack(ctx, action)
	}
	action = &validated

	state := h.coord.State()
	comp, unit, ok := findUnitFromInputType(state, action.InputType)
	if !ok {
		// If the matching action is not found ack the action with the error for action result document
		action.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
		action.CompletedAt = action.StartedAt
		action.Error = fmt.Sprintf("matching app is not found for action input: %s", action.InputType)
		return acker.Ack(ctx, action)
	}

	// Deserialize the action into map[string]interface{} for dispatching over to the apps
	params, err := action.MarshalMap()
	if err != nil {
		return err
	}

	start := time.Now().UTC()
	timeout := defaultActionTimeout
	if action.Timeout > 0 {
		timeout = time.Duration(action.Timeout) * time.Second
		if timeout > maxActionTimeout {
			h.log.Debugf("handlerAppAction: action '%v' timeout exceeds maximum allowed %v", action.InputType, maxActionTimeout)
			err = errActionTimeoutInvalid
		}
	}

	var res map[string]interface{}
	if err == nil {
		h.log.Debugf("handlerAppAction: action '%v' started with timeout: %v", action.ActionType, timeout)
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		res, err = h.coord.PerformAction(ctx, comp, unit, action.InputType, params)
	}
	end := time.Now().UTC()

	startFormatted := start.Format(time.RFC3339Nano)
	endFormatted := end.Format(time.RFC3339Nano)
	h.log.Debugf("handlerAppAction: action '%v' finished, startFormatted: %v, endFormatted: %v, err: %v", action.InputType, startFormatted, endFormatted, err)
	if err != nil {
		action.StartedAt = startFormatted
		action.CompletedAt = endFormatted
		action.Error = err.Error()
	} else {
		action.StartedAt = readMapString(res, "started_at", startFormatted)
		action.CompletedAt = readMapString(res, "completed_at", endFormatted)
		action.Error = readMapString(res, "error", "")
		appendActionResponse(action, action.InputType, res)
	}

	return acker.Ack(ctx, action)
}

var (
	none = struct{}{}

	// The set of action response fields are not included in the action_response property, because there are already set to top level fields
	excludeActionResponseFields = map[string]struct{}{
		"started_at":   none,
		"completed_at": none,
		"error":        none,
	}
)

// appendActionResponse appends the action response property with all the action response values excluding the ones specified in excludeActionResponseFields
//
//	"action_response": {
//		   "endpoint": {
//			   "acked": true
//		   }
//	 }
func appendActionResponse(action *fleetapi.ActionApp, inputType string, res map[string]interface{}) {
	if len(res) == 0 {
		return
	}

	m := make(map[string]interface{}, len(res))

	for k, v := range res {
		if _, ok := excludeActionResponseFields[k]; !ok {
			m[k] = v
		}
	}

	if len(m) > 0 {
		mt := make(map[string]interface{}, 1)
		mt[inputType] = m

		action.Response = mt
	}
}

func readMapString(m map[string]interface{}, key string, def string) string {
	if m == nil {
		return def
	}

	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return def
}

func findUnitFromInputType(state state.State, inputType string) (component.Component, component.Unit, bool) {
	for _, comp := range state.Components {
		for _, unit := range comp.Component.Units {
			if unit.Type == client.UnitTypeInput && unit.Config != nil && unit.Config.Type == inputType {
				return comp.Component, unit, true
			}
		}
	}
	return component.Component{}, component.Unit{}, false
}
