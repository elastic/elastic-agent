// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ess

import (
	"context"
	"encoding/json"
	"fmt"
)

type GetUserRequest struct {
	// For future use
}

type GetUserResponse struct {
	User struct {
		UserID int `json:"user_id"`
	} `json:"user"`
}

// GetUser returns information about the authenticated user
func (c *Client) GetUser(ctx context.Context, req GetUserRequest) (*GetUserResponse, error) {
	resp, err := c.doGet(ctx, "users")
	if err != nil {
		return nil, fmt.Errorf("error calling get user API: %w", err)
	}
	defer resp.Body.Close()

	var respBody GetUserResponse
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("error parsing get user response: %w", err)
	}

	return &respBody, nil
}
