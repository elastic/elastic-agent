// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package workflowrunner

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	// ActionName is the INPUT_ACTION input_type Kibana targets; the agent forwards
	// it to the component as the V2 action name.
	ActionName = "workflow/http"

	defaultTimeout = time.Minute
	// maxTimeout matches the upper bound enforced by the agent's AppAction handler.
	maxTimeout = time.Hour

	maxRedirectsLimit = 10

	bodyEncodingText   = "text"
	bodyEncodingBase64 = "base64"
)

var allowedMethods = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodHead:    {},
	http.MethodPost:    {},
	http.MethodPut:     {},
	http.MethodPatch:   {},
	http.MethodDelete:  {},
	http.MethodOptions: {},
}

// Request is the HTTP call a workflow step asks the runner to perform.
type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	// BodyEncoding is "text" (default) or "base64" for binary bodies.
	BodyEncoding string `json:"body_encoding"`
	// MaxRedirects is how many redirects to follow; 0 returns the redirect response.
	MaxRedirects int `json:"max_redirects"`
	// MaxResponseBytes lowers the stored response body cap; 0 uses the default.
	MaxResponseBytes int64 `json:"max_response_bytes"`
}

// ActionData is the workflow-specific payload Kibana puts in the action's data field.
type ActionData struct {
	SpaceID     string  `json:"space_id"`
	ExecutionID string  `json:"execution_id"`
	StepID      string  `json:"step_id"`
	Request     Request `json:"request"`
}

// action is the INPUT_ACTION as the agent forwards it to the component.
type action struct {
	ID             string     `json:"id"`
	TimeoutSeconds int64      `json:"timeout"`
	Data           ActionData `json:"data"`
}

type parsedAction struct {
	action
	target  *url.URL
	body    []byte
	timeout time.Duration
}

// parseAction converts the params map received over the control protocol into
// a validated action.
func parseAction(params map[string]interface{}) (parsedAction, error) {
	var p parsedAction
	raw, err := json.Marshal(params)
	if err != nil {
		return p, fmt.Errorf("encoding action params: %w", err)
	}
	if err := json.Unmarshal(raw, &p.action); err != nil {
		return p, fmt.Errorf("decoding action params: %w", err)
	}
	if p.ID == "" {
		return p, errors.New("action id is required")
	}

	p.timeout = defaultTimeout
	if p.TimeoutSeconds > 0 {
		p.timeout = time.Duration(p.TimeoutSeconds) * time.Second
	}
	if p.timeout > maxTimeout {
		return p, fmt.Errorf("action timeout %s exceeds maximum %s", p.timeout, maxTimeout)
	}

	req := p.Data.Request
	if _, ok := allowedMethods[req.Method]; !ok {
		return p, fmt.Errorf("unsupported HTTP method %q", req.Method)
	}
	target, err := url.Parse(req.URL)
	if err != nil {
		return p, errors.New("request url is not a valid URL")
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return p, fmt.Errorf("unsupported URL scheme %q; only http and https are allowed", target.Scheme)
	}
	if target.Hostname() == "" {
		return p, errors.New("request url has no host")
	}
	if target.User != nil {
		return p, errors.New("request url must not contain credentials; pass them as headers")
	}
	p.target = target

	switch req.BodyEncoding {
	case "", bodyEncodingText:
		p.body = []byte(req.Body)
	case bodyEncodingBase64:
		if p.body, err = base64.StdEncoding.DecodeString(req.Body); err != nil {
			return p, errors.New("request body is not valid base64")
		}
	default:
		return p, fmt.Errorf("unsupported body_encoding %q; use %q or %q", req.BodyEncoding, bodyEncodingText, bodyEncodingBase64)
	}

	if req.MaxRedirects < 0 || req.MaxRedirects > maxRedirectsLimit {
		return p, fmt.Errorf("max_redirects must be between 0 and %d", maxRedirectsLimit)
	}
	if req.MaxResponseBytes < 0 {
		return p, errors.New("max_response_bytes must not be negative")
	}
	return p, nil
}
