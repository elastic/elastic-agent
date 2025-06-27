// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOverallStatus(t *testing.T) {
	tests := map[string]struct {
		statuses              []string
		expectedOverallStatus string
	}{
		"single_started": {
			statuses:              []string{DeploymentStatusStarted},
			expectedOverallStatus: DeploymentStatusStarted,
		},
		"single_not_started": {
			statuses:              []string{DeploymentStatusReconfiguring},
			expectedOverallStatus: DeploymentStatusReconfiguring,
		},
		"multiple_none_started": {
			statuses:              []string{DeploymentStatusInitializing, DeploymentStatusReconfiguring},
			expectedOverallStatus: DeploymentStatusInitializing,
		},
		"multiple_some_started": {
			statuses:              []string{DeploymentStatusReconfiguring, DeploymentStatusStarted, DeploymentStatusInitializing},
			expectedOverallStatus: DeploymentStatusReconfiguring,
		},
		"multiple_all_started": {
			statuses:              []string{DeploymentStatusStarted, DeploymentStatusStarted, DeploymentStatusStarted},
			expectedOverallStatus: DeploymentStatusStarted,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actual := overallStatus(test.statuses...)
			require.Equal(t, test.expectedOverallStatus, actual)
		})
	}
}

func Test_generateCreateDeploymentRequestBody(t *testing.T) {
	type args struct {
		req       CreateDeploymentRequest
		cspValues []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Deployment request with docker overrides",
			args: args{
				req: CreateDeploymentRequest{
					Name:    "testd",
					Region:  "test-someregion",
					Version: "1.2.3",
					Tags:    nil,
				},
				cspValues: []byte(`
                    test:
                      integrations_server_conf_id: "gcp.integrationsserver.n2.68x32x45"
                      elasticsearch_conf_id: "gcp.es.datahot.n2.68x10x45"
                      elasticsearch_deployment_template_id: "gcp-storage-optimized"
                      kibana_instance_configuration_id: "gcp.kibana.n2.68x32x45"
                    docker:
                      integration_server_image: "docker.elastic.co/cloud-release/elastic-agent-cloud:1.2.3-foo-SNAPSHOT"
                      elasticsearch_image: "docker.elastic.co/cloud-release/elasticsearch-cloud-ess:1.2.3-foo-SNAPSHOT"
                      kibana_image: "docker.elastic.co/cloud-release/kibana-cloud:1.2.3-foo-SNAPSHOT"
`),
			},
			want: `
		{
          "resources": {
            "integrations_server": [
              {
                "elasticsearch_cluster_ref_id": "main-elasticsearch",
                "region": "test-someregion",
                "plan": {
                  "cluster_topology": [
                    {
                      "instance_configuration_id": "gcp.integrationsserver.n2.68x32x45",
                      "zone_count": 1,
                      "size": {
                        "resource": "memory",
                        "value": 1024
                      }
                    }
                  ],
                  "integrations_server": {
                    "version": "1.2.3",
                    "docker_image": "docker.elastic.co/cloud-release/elastic-agent-cloud:1.2.3-foo-SNAPSHOT"
                  }
                },
                "ref_id": "main-integrations_server"
              }
            ],
            "elasticsearch": [
              {
                "region": "test-someregion",
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
                    "version": "1.2.3",
                    "docker_image": "docker.elastic.co/cloud-release/elasticsearch-cloud-ess:1.2.3-foo-SNAPSHOT",
                    "enabled_built_in_plugins": []
                  },
                  "deployment_template": {
                    "id": "gcp-storage-optimized"
                  }
                },
                "ref_id": "main-elasticsearch"
              }
            ],
            "enterprise_search": [],
            "kibana": [
              {
                "elasticsearch_cluster_ref_id": "main-elasticsearch",
                "region": "test-someregion",
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
                    "version": "1.2.3",
                    "docker_image": "docker.elastic.co/cloud-release/kibana-cloud:1.2.3-foo-SNAPSHOT",
                    "user_settings_json": {
                      "xpack.fleet.enableExperimental": ["agentTamperProtectionEnabled"],
                      "xpack.fleet.internal.registry.kibanaVersionCheckEnabled": false,
                      "server.restrictInternalApis": false
                    }
                  }
                },
                "ref_id": "main-kibana"
              }
            ]
          },
          "settings": {
            "autoscaling_enabled": false
          },
          "name": "testd",
          "metadata": {
            "system_owned": false,
            "tags": null
          }
        }`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backupCsp := cloudProviderSpecificValues
			t.Cleanup(func() {
				cloudProviderSpecificValues = backupCsp
			})
			if tt.args.cspValues != nil {
				cloudProviderSpecificValues = tt.args.cspValues
			}
			got, err := generateCreateDeploymentRequestBody(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateCreateDeploymentRequestBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			actualJSON := string(got)
			t.Logf("JSON rendered: %s", actualJSON)
			assert.JSONEq(t, tt.want, actualJSON)
		})
	}
}

func TestGenerateUpgradeDeploymentRequestBody(t *testing.T) {
	got, err := generateUpgradeDeploymentRequestBody("us-east-1", "1.2.3")
	require.NoError(t, err)
	want := `{
    "prune_orphans": true,
    "resources": {
        "integrations_server": [
            {
                "elasticsearch_cluster_ref_id": "main-elasticsearch",
                "region": "us-east-1",
                "plan": {
                    "cluster_topology": [
                        {
                            "instance_configuration_id": "aws.integrationsserver.c5d",
                            "size": {
                                "value": 1024,
                                "resource": "memory"
                            },
                            "zone_count": 1
                        }
                    ],
                    "integrations_server": {
                        "version": "1.2.3"
                    }
                },
                "ref_id": "main-integrations_server"
            }
        ],
        "elasticsearch": [
            {
                "ref_id": "main-elasticsearch",
                "region": "us-east-1",
                "plan": {
                    "cluster_topology": [
                        {
                            "id": "hot_content",
                            "node_roles": [
                                "master",
                                "ingest",
                                "transform",
                                "data_hot",
                                "remote_cluster_client",
                                "data_content"
                            ],
                            "elasticsearch": {
                                "node_attributes": {
                                    "data": "hot"
                                }
                            },
                            "instance_configuration_id": "aws.es.datahot.i3",
                            "zone_count": 1,
                            "size": {
                                "value": 8192,
                                "resource": "memory"
                            }
                        }
                    ],
                    "elasticsearch": {
                        "version": "1.2.3"
                    },
                    "deployment_template": {
                        "id": "aws-storage-optimized"
                    }
                }
            }
        ],
        "kibana": [
            {
                "ref_id": "main-kibana",
                "elasticsearch_cluster_ref_id": "main-elasticsearch",
                "region": "us-east-1",
                "plan": {
                    "cluster_topology": [
                        {
                            "instance_configuration_id": "aws.kibana.c5d",
                            "size": {
                                "value": 1024,
                                "resource": "memory"
                            },
                            "zone_count": 1
                        }
                    ],
                    "kibana": {
                        "version": "1.2.3"
                    }
                }
            }
        ],
        "apm": [],
        "appsearch": [],
        "enterprise_search": []
    }
}
`
	require.Equal(t, want, string(got))
}
