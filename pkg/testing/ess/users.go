// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"context"
	"encoding/json"
	"fmt"
)

type GetAccountRequest struct {
	// For future use
}

type GetAccountResponse struct {
	ID string `json:"id"`
}

// GetAccount returns information about the authenticated user
func (c *Client) GetAccount(ctx context.Context, req GetAccountRequest) (*GetAccountResponse, error) {
	resp, err := c.doGet(ctx, "account")
	if err != nil {
		return nil, fmt.Errorf("error calling get user API: %w", err)
	}
	defer resp.Body.Close()

	var respBody GetAccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("error parsing get user response: %w", err)
	}

	return &respBody, nil
}
