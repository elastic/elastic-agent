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
	"net/url"
)

type CreateDeploymentRequest struct {
	Name    string `json:"name"`
	Region  string `json:"region"`
	Version string `json:"version"`
}

type CreateDeploymentResponse struct {
	ID string `json:"id"`

	ElasticsearchEndpoint string
	KibanaEndpoint        string

	Username string
	Password string
}

// CreateDeployment creates the deployment with the specified configuration.
func (c *Client) CreateDeployment(ctx context.Context, req CreateDeploymentRequest) (*CreateDeploymentResponse, error) {
	tpl, err := template.New("create_deployment_request").Parse(createDeploymentRequestTemplate)
	if err != nil {
		return nil, fmt.Errorf("unable to parse deployment creation template: %w", err)
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, req); err != nil {
		return nil, fmt.Errorf("unable to create deployment creation request body: %w", err)
	}

	res, err := c.doPost(
		ctx,
		"deployments",
		"application/json",
		&buf,
	)
	if err != nil {
		return nil, fmt.Errorf("error calling deployment creation API: %w", err)
	}
	defer res.Body.Close()

	var createRespBody struct {
		ID        string `json:"id"`
		Resources []struct {
			Kind        string `json:"kind"`
			Credentials struct {
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"credentials"`
		} `json:"resources"`
	}

	if err := json.NewDecoder(res.Body).Decode(&createRespBody); err != nil {
		return nil, fmt.Errorf("error parsing deployment creation API response: %w", err)
	}

	r := CreateDeploymentResponse{
		ID: createRespBody.ID,
	}

	for _, resource := range createRespBody.Resources {
		if resource.Kind == "elasticsearch" {
			r.Username = resource.Credentials.Username
			r.Password = resource.Credentials.Password
			break
		}
	}

	// Get Elasticsearch and Kibana endpoint URLs
	u, err := url.JoinPath("deployments", r.ID)
	if err != nil {
		return nil, fmt.Errorf("unable to create deployment retrieval API URL: %w", err)
	}

	res, err = c.doGet(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("error calling deployment retrieval API: %w", err)
	}
	defer res.Body.Close()

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

	if err := json.NewDecoder(res.Body).Decode(&getRespBody); err != nil {
		return nil, fmt.Errorf("error parsing deployment retrieval API response: %w", err)
	}

	r.ElasticsearchEndpoint = getRespBody.Resources.Elasticsearch[0].Info.Metadata.ServiceUrl
	r.KibanaEndpoint = getRespBody.Resources.Kibana[0].Info.Metadata.ServiceUrl

	return &r, nil
}

// ShutdownDeployment attempts to shut down the ESS deployment with the specified ID.
func (c *Client) ShutdownDeployment(ctx context.Context, deploymentID string) error {
	u, err := url.JoinPath("deployments", deploymentID, "_shutdown")
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
