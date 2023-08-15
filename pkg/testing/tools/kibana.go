package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/elastic/elastic-agent-libs/kibana"
)

type DashboardResponse struct {
	Page         int         `json:"page"`
	PerPage      int         `json:"per_page"`
	Total        int         `json:"total"`
	SavedObjects []Dashboard `json:"saved_objects"`
}

type Dashboard struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Namespaces []string `json:"namespaces"`
}

// GetDashboards returns a list of known dashboards on the system
func GetDashboards(ctx context.Context, client *kibana.Client) ([]Dashboard, error) {
	params := url.Values{}
	params.Add("type", "dashboard")
	params.Add("page", "1")

	dashboards := []Dashboard{}
	page := 1
	for {
		status, resp, err := client.Connection.Request("GET", "/api/saved_objects/_find", params, nil, nil)
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
