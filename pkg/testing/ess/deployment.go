// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"
)

type CreateDeploymentResponse struct {
	ID string `json:"id"`

	ElasticsearchEndpoint string
	KibanaEndpoint        string

	Username string
	Password string
}

type GetDeploymentResponse struct {
	Elasticsearch struct {
		Status     DeploymentStatus
		ServiceUrl string
	}
	Kibana struct {
		Status     DeploymentStatus
		ServiceUrl string
	}
	IntegrationsServer struct {
		Status     DeploymentStatus
		ServiceUrl string
	}
}

type DeploymentStatus string

func (d *DeploymentStatus) UnmarshalJSON(data []byte) error {
	var status string
	if err := json.Unmarshal(data, &status); err != nil {
		return err
	}

	switch status {
	case string(DeploymentStatusInitializing), string(DeploymentStatusReconfiguring), string(DeploymentStatusStarted):
		*d = DeploymentStatus(status)
	default:
		return fmt.Errorf("unknown status: [%s]", status)
	}

	return nil
}

func (d *DeploymentStatus) String() string {
	return string(*d)
}

const (
	DeploymentStatusInitializing  DeploymentStatus = "initializing"
	DeploymentStatusReconfiguring DeploymentStatus = "reconfiguring"
	DeploymentStatusStarted       DeploymentStatus = "started"
)

type DeploymentStatusResponse struct {
	Overall DeploymentStatus

	Elasticsearch      DeploymentStatus
	Kibana             DeploymentStatus
	IntegrationsServer DeploymentStatus
}

// CreateDeployment creates the deployment with the specified configuration.
func (c *Client) CreateDeployment(ctx context.Context, req CreateDeploymentRequest) (*CreateResponse, error) {
	tpl, err := template.New("create_deployment_request").Parse(createDeploymentRequestTemplate)
	if err != nil {
		return nil, fmt.Errorf("unable to parse deployment creation template: %w", err)
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, req); err != nil {
		return nil, fmt.Errorf("unable to create deployment creation request body: %w", err)
	}

	createResp, err := c.doPost(
		ctx,
		"deployments",
		"application/json",
		&buf,
	)
	if err != nil {
		return nil, fmt.Errorf("error calling deployment creation API: %w", err)
	}
	defer createResp.Body.Close()

	var createRespBody struct {
		ID        string `json:"id"`
		Resources []struct {
			Kind        string `json:"kind"`
			Credentials struct {
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"credentials"`
		} `json:"resources"`
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(createResp.Body).Decode(&createRespBody); err != nil {
		return nil, fmt.Errorf("error parsing deployment creation API response: %w", err)
	}

	if len(createRespBody.Errors) > 0 {
		return nil, fmt.Errorf("failed to create: (%s) %s", createRespBody.Errors[0].Code, createRespBody.Errors[0].Message)
	}

	createReturn := CreateResponse{
		ID: createRespBody.ID,
	}

	for _, resource := range createRespBody.Resources {
		if resource.Kind == "elasticsearch" {
			createReturn.ESUser = resource.Credentials.Username
			createReturn.ESPassword = resource.Credentials.Password
			break
		}
	}

	// Get Elasticsearch and Kibana endpoint URLs
	getResp, err := c.getDeployment(ctx, createReturn.ID)
	if err != nil {
		return nil, fmt.Errorf("error calling deployment retrieval API: %w", err)
	}
	defer getResp.Body.Close()

	var getRespBody struct {
		Resources struct {
			Elasticsearch []struct {
				Info struct {
					Metadata struct {
						ServiceUrl string `json:"service_url"`
					} `json:"metadata"`
				} `json:"info"`
			} `json:"elasticsearch"`
			Kibana []struct {
				Info struct {
					Metadata struct {
						ServiceUrl string `json:"service_url"`
					} `json:"metadata"`
				} `json:"info"`
			} `json:"kibana"`
		} `json:"resources"`
	}

	if err := json.NewDecoder(getResp.Body).Decode(&getRespBody); err != nil {
		return nil, fmt.Errorf("error parsing deployment retrieval API response: %w", err)
	}

	createReturn.ElasticsearchEndpoint = getRespBody.Resources.Elasticsearch[0].Info.Metadata.ServiceUrl
	createReturn.KibanaEndpoint = getRespBody.Resources.Kibana[0].Info.Metadata.ServiceUrl
	c.deploymentID = createReturn.ID
	return &createReturn, nil
}

// ShutdownDeployment attempts to shut down the ESS deployment with the specified ID.
func (c *Client) ShutdownDeployment(ctx context.Context) error {
	if c.deploymentID == "" {
		return ErrDeploymentDoesNotExist
	}
	u, err := url.JoinPath("deployments", c.deploymentID, "_shutdown")
	if err != nil {
		return fmt.Errorf("unable to create deployment shutdown API URL: %w", err)
	}

	res, err := c.doPost(ctx, u, "", nil)
	if err != nil {
		return fmt.Errorf("error calling deployment shutdown API: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("got unexpected response code [%d] from deployment shutdown API", res.StatusCode)
	}

	return nil
}

// DeploymentStatus returns the overall status of the deployment as well as statuses of every component.
func (c *Client) DeploymentStatus(ctx context.Context, deploymentID string) (*DeploymentStatusResponse, error) {
	getResp, err := c.getDeployment(ctx, deploymentID)
	if err != nil {
		return nil, fmt.Errorf("error calling deployment retrieval API: %w", err)
	}
	defer getResp.Body.Close()

	var getRespBody struct {
		Resources struct {
			Elasticsearch []struct {
				Info struct {
					Status DeploymentStatus `json:"status"`
				} `json:"info"`
			} `json:"elasticsearch"`
			Kibana []struct {
				Info struct {
					Status DeploymentStatus `json:"status"`
				} `json:"info"`
			} `json:"kibana"`
			IntegrationsServer []struct {
				Info struct {
					Status DeploymentStatus `json:"status"`
				} `json:"info"`
			} `json:"integrations_server"`
		} `json:"resources"`
	}

	if err := json.NewDecoder(getResp.Body).Decode(&getRespBody); err != nil {
		return nil, fmt.Errorf("error parsing deployment retrieval API response: %w", err)
	}

	s := DeploymentStatusResponse{
		Elasticsearch:      getRespBody.Resources.Elasticsearch[0].Info.Status,
		Kibana:             getRespBody.Resources.Kibana[0].Info.Status,
		IntegrationsServer: getRespBody.Resources.IntegrationsServer[0].Info.Status,
	}
	s.Overall = overallStatus(s.Elasticsearch, s.Kibana, s.IntegrationsServer)

	return &s, nil
}

// DeploymentIsReady returns true when the deployment is ready, checking its status
// every `tick` until `waitFor` duration.
func (c *Client) DeploymentIsReady(ctx context.Context, tick time.Duration) (bool, error) {
	if c.deploymentID == "" {
		return false, ErrDeploymentDoesNotExist
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	statusCh := make(chan DeploymentStatus, 1)
	errCh := make(chan error)

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
			statusCtx, statusCancel := context.WithTimeout(ctx, tick)
			defer statusCancel()
			go func() {
				status, err := c.DeploymentStatus(statusCtx, c.deploymentID)
				if err != nil {
					errCh <- err
					return
				}
				statusCh <- status.Overall
			}()
		case status := <-statusCh:
			if status == DeploymentStatusStarted {
				return true, nil
			}
		case err := <-errCh:
			return false, err
		}
	}
}

func (c *Client) getDeployment(ctx context.Context, deploymentID string) (*http.Response, error) {
	u, err := url.JoinPath("deployments", deploymentID)
	if err != nil {
		return nil, fmt.Errorf("unable to create deployment retrieval API URL: %w", err)
	}

	return c.doGet(ctx, u)
}

func overallStatus(statuses ...DeploymentStatus) DeploymentStatus {
	// The overall status is started if every component's status is started. Otherwise,
	// we take the non-started components' statuses and pick the first one as the overall
	// status.
	statusMap := map[DeploymentStatus]struct{}{}
	for _, status := range statuses {
		statusMap[status] = struct{}{}
	}

	if len(statusMap) == 1 {
		if _, allStarted := statusMap[DeploymentStatusStarted]; allStarted {
			return DeploymentStatusStarted
		}
	}

	var overallStatus DeploymentStatus
	for _, status := range statuses {
		if status != DeploymentStatusStarted {
			overallStatus = status
			break
		}
	}

	return overallStatus
}

// TODO: make work for cloud other than GCP
const createDeploymentRequestTemplate = `
{
  "resources": {
    "integrations_server": [
      {
        "elasticsearch_cluster_ref_id": "main-elasticsearch",
        "region": "{{ .Region }}",
        "plan": {
          "cluster_topology": [
            {
              "instance_configuration_id": "gcp.integrationsserver.n2.68x32x45.2",
              "zone_count": 1,
              "size": {
                "resource": "memory",
                "value": 1024
              }
            }
          ],
          "integrations_server": {
            "version": "{{ .Version }}"
          }
        },
        "ref_id": "main-integrations_server"
      }
    ],
    "elasticsearch": [
      {
        "region": "{{ .Region }}",
        "settings": {
          "dedicated_masters_threshold": 6
        },
        "plan": {
          "cluster_topology": [
            {
              "zone_count": 1,
              "elasticsearch": {
                "node_attributes": {
                  "data": "hot"
                }
              },
              "instance_configuration_id": "gcp.es.datahot.n2.68x10x45",
              "node_roles": [
                "master",
                "ingest",
                "transform",
                "data_hot",
                "remote_cluster_client",
                "data_content"
              ],
              "id": "hot_content",
              "size": {
                "resource": "memory",
                "value": 8192
              }
            }
          ],
          "elasticsearch": {
            "version": "{{ .Version }}",
            "enabled_built_in_plugins": []
          },
          "deployment_template": {
            "id": "gcp-storage-optimized-v5"
          }
        },
        "ref_id": "main-elasticsearch"
      }
    ],
    "enterprise_search": [],
    "kibana": [
      {
        "elasticsearch_cluster_ref_id": "main-elasticsearch",
        "region": "{{ .Region }}",
        "plan": {
          "cluster_topology": [
            {
              "instance_configuration_id": "gcp.kibana.n2.68x32x45",
              "zone_count": 1,
              "size": {
                "resource": "memory",
                "value": 1024
              }
            }
          ],
          "kibana": {
            "version": "{{ .Version }}"
          }
        },
        "ref_id": "main-kibana"
      }
    ]
  },
  "settings": {
    "autoscaling_enabled": false
  },
  "name": "{{ .Name }}",
  "metadata": {
    "system_owned": false
  }
}`
