// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
)

type DashboardResponse struct {
	Page         int         `json:"page"`
	PerPage      int         `json:"per_page"`
	Total        int         `json:"total"`
	SavedObjects []Dashboard `json:"saved_objects"`
}

type Dashboard struct {
	Type       string    `json:"type"`
	ID         string    `json:"id"`
	Namespaces []string  `json:"namespaces"`
	UpdatedAt  time.Time `json:"updated_at"`
	CreatedAt  time.Time `json:"created_at"`
	Version    string    `json:"version"`
}

// DeleteDashboard removes the selected dashboard
func DeleteDashboard(ctx context.Context, client *kibana.Client, id string) error {
	// In the future there should be logic to check if we need this header, waiting for https://github.com/elastic/kibana/pull/164850
	headers := http.Header{}
	headers.Add("x-elastic-internal-origin", "integration-tests")
	status, resp, err := client.Connection.Request("DELETE", fmt.Sprintf("/api/saved_objects/dashboard/%s", id), nil, headers, nil)
	if err != nil {
		return fmt.Errorf("error making API request: %w, response: '%s'", err, string(resp))
	}

	if status != 200 {
		return fmt.Errorf("non-200 return code: %v, response: '%s'", status, string(resp))
	}
	return nil

}

// GetDashboards returns a list of known dashboards on the system
func GetDashboards(ctx context.Context, client *kibana.Client) ([]Dashboard, error) {
	params := url.Values{}
	params.Add("type", "dashboard")
	params.Add("page", "1")

	dashboards := []Dashboard{}
	page := 1
	for {
		headers := http.Header{}
		headers.Add("x-elastic-internal-origin", "integration-tests")
		status, resp, err := client.Connection.Request("GET", "/api/saved_objects/_find", params, headers, nil)
		if err != nil {
			return nil, fmt.Errorf("error making api request: %w", err)
		}

		if status != 200 {
			return nil, fmt.Errorf("non-200 return code: %v, response: '%s'", status, string(resp))
		}

		dashResp := DashboardResponse{}
		err = json.Unmarshal(resp, &dashResp)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling dashboard response: %w", err)
		}
		if len(dashResp.SavedObjects) == 0 {
			break
		}

		dashboards = append(dashboards, dashResp.SavedObjects...)
		// we got all the results in one page
		if dashResp.Total == dashResp.PerPage {
			break
		}
		// we COULD calculate the number of pages we need to ask for in total, or just keep iterating until we don't get any results
		page++
		params.Set("page", fmt.Sprintf("%d", page))
	}

	return dashboards, nil
}
