// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v2"
)

type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type CreateDeploymentRequest struct {
	Name    string `json:"name"`
	Region  string `json:"region"`
	Version string `json:"version"`
	Tags    []Tag  `json:"tags"`
}

type CreateDeploymentResponse struct {
	ID string `json:"id"`

	ElasticsearchEndpoint      string
	KibanaEndpoint             string
	IntegrationsServerEndpoint string

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
func (c *Client) CreateDeployment(ctx context.Context, req CreateDeploymentRequest) (*CreateDeploymentResponse, error) {
	reqBodyBytes, err := generateCreateDeploymentRequestBody(req)
	if err != nil {
		return nil, err
	}

	createResp, err := c.doPost(
		ctx,
		"deployments",
		"application/json",
		bytes.NewReader(reqBodyBytes),
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
	getResp, err := c.getDeployment(ctx, r.ID)
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
			IntegrationsServer []struct {
				Info struct {
					Metadata struct {
						ServiceUrl string `json:"service_url"`
					} `json:"metadata"`
				} `json:"info"`
			} `json:"integrations_server"`
		} `json:"resources"`
	}

	if err := json.NewDecoder(getResp.Body).Decode(&getRespBody); err != nil {
		return nil, fmt.Errorf("error parsing deployment retrieval API response: %w", err)
	}

	r.ElasticsearchEndpoint = getRespBody.Resources.Elasticsearch[0].Info.Metadata.ServiceUrl
	r.KibanaEndpoint = getRespBody.Resources.Kibana[0].Info.Metadata.ServiceUrl
	r.IntegrationsServerEndpoint = getRespBody.Resources.IntegrationsServer[0].Info.Metadata.ServiceUrl

	return &r, nil
}

// UpgradeDeployment upgrades the specified deployment to the specified version.
func (c *Client) UpgradeDeployment(ctx context.Context, deploymentID string, version string) error {
	u, err := url.JoinPath("deployments", deploymentID)
	if err != nil {
		return fmt.Errorf("unable to create deployment update API URL: %w", err)
	}

	// Get deployment
	resp, err := c.doGet(ctx, u)
	if err != nil {
		return fmt.Errorf("unable to GET deployment: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read body of GET deployment API response: %w", err)
	}

	bodyStr := string(data)

	// Parse out current version from body
	var bodyObj struct {
		Resources struct {
			Elasticsearch []struct {
				Info struct {
					PlanInfo struct {
						Current struct {
							Plan struct {
								Elasticsearch struct {
									Version string `json:"version"`
								} `json:"elasticsearch"`
							} `json:"plan"`
						} `json:"current"`
					} `json:"plan_info"`
				} `json:"info"`
			} `json:"elasticsearch"`
		} `json:"resources"`
	}
	err = json.Unmarshal(data, &bodyObj)
	if err != nil {
		return fmt.Errorf("unable to parse current deployment version from GET deployment API response: %w", err)
	}

	// Replace current version in body with

	// See also: https://www.elastic.co/docs/api/doc/cloud/operation/operation-update-deployment
	// - Only elements that change (version?) could be specified?
	// See also: create_deployment_request.tmpl.json
	//{
	// "name": "test-8181",
	// "alias": "test-8181",
	// "prune_orphans": true,
	// "metadata": {
	//   "system_owned": false,
	//   "hidden": false
	// },
	// "settings": {
	//   "autoscaling_enabled": false
	// },
	// "resources": {
	//   "elasticsearch": [
	//     {
	//       "region": "gcp-us-west2",
	//       "ref_id": "main-elasticsearch",
	//       "plan": {
	//         "tiebreaker_topology": {
	//           "memory_per_node": 1024
	//         },
	//         "cluster_topology": [
	//           {
	//             "id": "hot_content",
	//             "node_roles": [
	//               "master",
	//               "ingest",
	//               "transform",
	//               "data_hot",
	//               "remote_cluster_client",
	//               "data_content"
	//             ],
	//             "zone_count": 2,
	//             "elasticsearch": {
	//               "system_settings": {
	//                 "scripting": {
	//                   "stored": {
	//                     "enabled": true
	//                   },
	//                   "inline": {
	//                     "enabled": true
	//                   }
	//                 },
	//                 "http": {
	//                   "compression": true,
	//                   "cors_enabled": false,
	//                   "cors_max_age": 1728000,
	//                   "cors_allow_credentials": false
	//                 },
	//                 "reindex_whitelist": [],
	//                 "auto_create_index": true,
	//                 "enable_close_index": true,
	//                 "destructive_requires_name": false,
	//                 "monitoring_collection_interval": -1,
	//                 "monitoring_history_duration": "3d"
	//               },
	//               "node_attributes": {
	//                 "data": "hot"
	//               }
	//             },
	//             "instance_configuration_id": "gcp.es.datahot.n2.68x10x45",
	//             "instance_configuration_version": 1,
	//             "size": {
	//               "value": 8192,
	//               "resource": "memory"
	//             },
	//             "autoscaling_max": {
	//               "value": 131072,
	//               "resource": "memory"
	//             }
	//           },
	//           {
	//             "id": "warm",
	//             "node_roles": [
	//               "data_warm",
	//               "remote_cluster_client"
	//             ],
	//             "zone_count": 2,
	//             "elasticsearch": {
	//               "system_settings": {
	//                 "scripting": {
	//                   "stored": {
	//                     "enabled": true
	//                   },
	//                   "inline": {
	//                     "enabled": true
	//                   }
	//                 },
	//                 "http": {
	//                   "compression": true,
	//                   "cors_enabled": false,
	//                   "cors_max_age": 1728000,
	//                   "cors_allow_credentials": false
	//                 },
	//                 "reindex_whitelist": [],
	//                 "auto_create_index": true,
	//                 "enable_close_index": true,
	//                 "destructive_requires_name": false,
	//                 "monitoring_collection_interval": -1,
	//                 "monitoring_history_duration": "3d"
	//               },
	//               "node_attributes": {
	//                 "data": "warm"
	//               }
	//             },
	//             "instance_configuration_id": "gcp.es.datawarm.n2.68x10x190",
	//             "instance_configuration_version": 1,
	//             "size": {
	//               "value": 0,
	//               "resource": "memory"
	//             },
	//             "autoscaling_max": {
	//               "value": 131072,
	//               "resource": "memory"
	//             }
	//           },
	//           {
	//             "id": "cold",
	//             "node_roles": [
	//               "data_cold",
	//               "remote_cluster_client"
	//             ],
	//             "zone_count": 1,
	//             "elasticsearch": {
	//               "system_settings": {
	//                 "scripting": {
	//                   "stored": {
	//                     "enabled": true
	//                   },
	//                   "inline": {
	//                     "enabled": true
	//                   }
	//                 },
	//                 "http": {
	//                   "compression": true,
	//                   "cors_enabled": false,
	//                   "cors_max_age": 1728000,
	//                   "cors_allow_credentials": false
	//                 },
	//                 "reindex_whitelist": [],
	//                 "auto_create_index": true,
	//                 "enable_close_index": true,
	//                 "destructive_requires_name": false,
	//                 "monitoring_collection_interval": -1,
	//                 "monitoring_history_duration": "3d"
	//               },
	//               "node_attributes": {
	//                 "data": "cold"
	//               }
	//             },
	//             "instance_configuration_id": "gcp.es.datacold.n2.68x10x190",
	//             "instance_configuration_version": 1,
	//             "size": {
	//               "value": 0,
	//               "resource": "memory"
	//             },
	//             "autoscaling_max": {
	//               "value": 65536,
	//               "resource": "memory"
	//             }
	//           },
	//           {
	//             "id": "frozen",
	//             "node_roles": [
	//               "data_frozen"
	//             ],
	//             "zone_count": 1,
	//             "elasticsearch": {
	//               "system_settings": {
	//                 "scripting": {
	//                   "stored": {
	//                     "enabled": true
	//                   },
	//                   "inline": {
	//                     "enabled": true
	//                   }
	//                 },
	//                 "http": {
	//                   "compression": true,
	//                   "cors_enabled": false,
	//                   "cors_max_age": 1728000,
	//                   "cors_allow_credentials": false
	//                 },
	//                 "reindex_whitelist": [],
	//                 "auto_create_index": true,
	//                 "enable_close_index": true,
	//                 "destructive_requires_name": false,
	//                 "monitoring_collection_interval": -1,
	//                 "monitoring_history_duration": "3d"
	//               },
	//               "node_attributes": {
	//                 "data": "frozen"
	//               }
	//             },
	//             "instance_configuration_id": "gcp.es.datafrozen.n2.68x10x90",
	//             "instance_configuration_version": 1,
	//             "size": {
	//               "value": 0,
	//               "resource": "memory"
	//             },
	//             "autoscaling_max": {
	//               "value": 131072,
	//               "resource": "memory"
	//             }
	//           },
	//           {
	//             "id": "master",
	//             "node_roles": [
	//               "master",
	//               "remote_cluster_client"
	//             ],
	//             "zone_count": 3,
	//             "elasticsearch": {
	//               "system_settings": {
	//                 "scripting": {
	//                   "stored": {
	//                     "enabled": true
	//                   },
	//                   "inline": {
	//                     "enabled": true
	//                   }
	//                 },
	//                 "http": {
	//                   "compression": true,
	//                   "cors_enabled": false,
	//                   "cors_max_age": 1728000,
	//                   "cors_allow_credentials": false
	//                 },
	//                 "reindex_whitelist": [],
	//                 "auto_create_index": true,
	//                 "enable_close_index": true,
	//                 "destructive_requires_name": false,
	//                 "monitoring_collection_interval": -1,
	//                 "monitoring_history_duration": "3d"
	//               }
	//             },
	//             "instance_configuration_id": "gcp.es.master.n2.68x32x45",
	//             "instance_configuration_version": 2,
	//             "size": {
	//               "value": 0,
	//               "resource": "memory"
	//             }
	//           },
	//           {
	//             "id": "coordinating",
	//             "node_roles": [
	//               "ingest",
	//               "remote_cluster_client"
	//             ],
	//             "zone_count": 2,
	//             "elasticsearch": {
	//               "system_settings": {
	//                 "scripting": {
	//                   "stored": {
	//                     "enabled": true
	//                   },
	//                   "inline": {
	//                     "enabled": true
	//                   }
	//                 },
	//                 "http": {
	//                   "compression": true,
	//                   "cors_enabled": false,
	//                   "cors_max_age": 1728000,
	//                   "cors_allow_credentials": false
	//                 },
	//                 "reindex_whitelist": [],
	//                 "auto_create_index": true,
	//                 "enable_close_index": true,
	//                 "destructive_requires_name": false,
	//                 "monitoring_collection_interval": -1,
	//                 "monitoring_history_duration": "3d"
	//               }
	//             },
	//             "instance_configuration_id": "gcp.es.coordinating.n2.68x16x45",
	//             "instance_configuration_version": 1,
	//             "size": {
	//               "value": 0,
	//               "resource": "memory"
	//             }
	//           },
	//           {
	//             "id": "ml",
	//             "node_roles": [
	//               "ml",
	//               "remote_cluster_client"
	//             ],
	//             "zone_count": 1,
	//             "elasticsearch": {
	//               "system_settings": {
	//                 "scripting": {
	//                   "stored": {
	//                     "enabled": true
	//                   },
	//                   "inline": {
	//                     "enabled": true
	//                   }
	//                 },
	//                 "http": {
	//                   "compression": true,
	//                   "cors_enabled": false,
	//                   "cors_max_age": 1728000,
	//                   "cors_allow_credentials": false
	//                 },
	//                 "reindex_whitelist": [],
	//                 "auto_create_index": true,
	//                 "enable_close_index": true,
	//                 "destructive_requires_name": false,
	//                 "monitoring_collection_interval": -1,
	//                 "monitoring_history_duration": "3d"
	//               }
	//             },
	//             "instance_configuration_id": "gcp.es.ml.n2.68x32x45",
	//             "instance_configuration_version": 1,
	//             "autoscaling_min": {
	//               "value": 0,
	//               "resource": "memory"
	//             },
	//             "autoscaling_max": {
	//               "value": 65536,
	//               "resource": "memory"
	//             },
	//             "autoscaling_tier_override": true
	//           }
	//         ],
	//         "elasticsearch": {
	//           "version": "8.19.0-SNAPSHOT",
	//           "enabled_built_in_plugins": [],
	//           "user_bundles": [],
	//           "user_plugins": []
	//         },
	//         "deployment_template": {
	//           "id": "gcp-storage-optimized"
	//         },
	//         "transient": {
	//           "strategy": {
	//             "autodetect": {}
	//           }
	//         }
	//       }
	//     }
	//   ],
	//   "kibana": [
	//     {
	//       "region": "gcp-us-west2",
	//       "ref_id": "main-kibana",
	//       "elasticsearch_cluster_ref_id": "main-elasticsearch",
	//       "plan": {
	//         "cluster_topology": [
	//           {
	//             "instance_configuration_id": "gcp.kibana.n2.68x32x45",
	//             "instance_configuration_version": 1,
	//             "size": {
	//               "value": 1024,
	//               "resource": "memory"
	//             },
	//             "zone_count": 1,
	//             "kibana": {
	//               "system_settings": {}
	//             }
	//           }
	//         ],
	//         "kibana": {
	//           "version": "8.19.0-SNAPSHOT"
	//         },
	//         "transient": {
	//           "strategy": {
	//             "autodetect": {}
	//           }
	//         }
	//       }
	//     }
	//   ],
	//   "apm": [],
	//   "integrations_server": [
	//     {
	//       "region": "gcp-us-west2",
	//       "ref_id": "main-integrations_server",
	//       "elasticsearch_cluster_ref_id": "main-elasticsearch",
	//       "plan": {
	//         "cluster_topology": [
	//           {
	//             "instance_configuration_id": "gcp.integrationsserver.n2.68x32x45",
	//             "instance_configuration_version": 1,
	//             "size": {
	//               "value": 1024,
	//               "resource": "memory"
	//             },
	//             "zone_count": 1,
	//             "integrations_server": {
	//               "system_settings": {
	//                 "debug_enabled": false
	//               }
	//             }
	//           }
	//         ],
	//         "integrations_server": {
	//           "version": "8.19.0-SNAPSHOT",
	//           "system_settings": {
	//             "secret_token": "TxdKLGthVCBamTXdCL"
	//           }
	//         },
	//         "transient": {
	//           "strategy": {
	//             "autodetect": {}
	//           }
	//         }
	//       }
	//     }
	//   ],
	//   "appsearch": [],
	//   "enterprise_search": [
	//     {
	//       "region": "gcp-us-west2",
	//       "ref_id": "main-enterprise_search",
	//       "elasticsearch_cluster_ref_id": "main-elasticsearch",
	//       "plan": {
	//         "cluster_topology": [
	//           {
	//             "node_type": {
	//               "appserver": true,
	//               "worker": true,
	//               "connector": true
	//             },
	//             "instance_configuration_id": "gcp.enterprisesearch.n2.68x32x45",
	//             "instance_configuration_version": 1,
	//             "size": {
	//               "value": 2048,
	//               "resource": "memory"
	//             },
	//             "zone_count": 1,
	//             "enterprise_search": {
	//               "system_settings": {}
	//             }
	//           }
	//         ],
	//         "enterprise_search": {
	//           "version": "8.19.0-SNAPSHOT",
	//           "system_settings": {}
	//         },
	//         "transient": {
	//           "strategy": {
	//             "autodetect": {}
	//           }
	//         }
	//       }
	//     }
	//   ]
	// }
	//}

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
		resBytes, _ := io.ReadAll(res.Body)
		return fmt.Errorf("got unexpected response code [%d] from deployment shutdown API: %s", res.StatusCode, string(resBytes))
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
func (c *Client) DeploymentIsReady(ctx context.Context, deploymentID string, tick time.Duration) (bool, error) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	var errs error
	statusCh := make(chan DeploymentStatus, 1)
	for {
		select {
		case <-ctx.Done():
			return false, errors.Join(errs, ctx.Err())
		case <-ticker.C:
			go func() {
				statusCtx, statusCancel := context.WithTimeout(ctx, tick)
				defer statusCancel()
				status, err := c.DeploymentStatus(statusCtx, deploymentID)
				if err != nil {
					errs = errors.Join(errs, err)
					return
				}
				statusCh <- status.Overall
			}()
		case status := <-statusCh:
			if status == DeploymentStatusStarted {
				return true, nil
			}
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

//go:embed create_deployment_request.tmpl.json
var createDeploymentRequestTemplate string

//go:embed create_deployment_csp_configuration.yaml
var cloudProviderSpecificValues []byte

func generateCreateDeploymentRequestBody(req CreateDeploymentRequest) ([]byte, error) {
	var csp string
	// Special case: AWS us-east-1 region is just called
	// us-east-1 (instead of aws-us-east-1)!
	if req.Region == "us-east-1" {
		csp = "aws"
	} else {
		regionParts := strings.Split(req.Region, "-")
		if len(regionParts) < 2 {
			return nil, fmt.Errorf("unable to parse CSP out of region [%s]", req.Region)
		}

		csp = regionParts[0]
	}
	templateContext, err := createDeploymentTemplateContext(csp, req)
	if err != nil {
		return nil, fmt.Errorf("creating request template context: %w", err)
	}

	tpl, err := template.New("create_deployment_request").
		Funcs(template.FuncMap{"json": jsonMarshal}).
		Parse(createDeploymentRequestTemplate)
	if err != nil {
		return nil, fmt.Errorf("unable to parse deployment creation template: %w", err)
	}

	var bBuf bytes.Buffer
	err = tpl.Execute(&bBuf, templateContext)
	if err != nil {
		return nil, fmt.Errorf("rendering create deployment request template with context %v : %w", templateContext, err)
	}
	return bBuf.Bytes(), nil
}

func jsonMarshal(in any) (string, error) {
	jsonBytes, err := json.Marshal(in)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

func createDeploymentTemplateContext(csp string, req CreateDeploymentRequest) (map[string]any, error) {
	cspSpecificContext, err := loadCspValues(csp)
	if err != nil {
		return nil, fmt.Errorf("loading csp-specific values for %q: %w", csp, err)
	}

	cspSpecificContext["request"] = req

	return cspSpecificContext, nil
}

func loadCspValues(csp string) (map[string]any, error) {
	var cspValues map[string]map[string]any

	err := yaml.Unmarshal(cloudProviderSpecificValues, &cspValues)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling error: %w", err)
	}
	values, supportedCSP := cspValues[csp]
	if !supportedCSP {
		return nil, fmt.Errorf("csp %s not supported", csp)
	}

	// check for docker overrides
	if dockerValues, dockerValuesFound := cspValues["docker"]; dockerValuesFound {
		values["docker"] = dockerValues
	}

	return values, nil
}
