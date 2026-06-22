// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/ecsmeta"
	pkgfleetapi "github.com/elastic/elastic-agent/pkg/fleetapi"
)

type agentinfo struct{}

func (*agentinfo) AgentID() string { return "id" }

func TestCheckin(t *testing.T) {
	const withAPIKey = "secret"
	const requestDelay = time.Millisecond
	ctx := context.Background()
	agentInfo := &agentinfo{}
	defaultCompression := configuration.DefaultFleetCheckin().GetCompression()

	t.Run("Propagate any errors from the server", withServerWithAuthClient(
		func(t *testing.T) *http.ServeMux {
			raw := `
	Something went wrong
	}
	`
			mux := http.NewServeMux()
			path := fmt.Sprintf("/api/fleet/agents/%s/checkin", agentInfo.AgentID())
			mux.HandleFunc(path, authHandler(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, raw)
				// Introduce a small delay to test the request time measurment.
				time.Sleep(requestDelay)
			}, withAPIKey))
			return mux
		}, withAPIKey,
		func(t *testing.T, client client.Sender) {
			cmd := pkgfleetapi.NewCheckinCmd(agentInfo, client, defaultCompression)

			request := pkgfleetapi.CheckinRequest{}

			_, took, err := cmd.Execute(ctx, &request)
			require.Error(t, err)
			// Ensure the request took at least as long as the artificial delay.
			require.GreaterOrEqual(t, took, requestDelay)
		},
	))

	t.Run("Checkin receives a PolicyChange", withServerWithAuthClient(
		func(t *testing.T) *http.ServeMux {
			raw := `
	{
		"actions": [{
			"type": "POLICY_CHANGE",
			"id": "id1",
			"data": {
				"policy": {
					"id": "policy-id",
					"outputs": {
						"default": {
							"hosts": "https://localhost:9200"
						}
					},
					"datasources": [{
						"id": "string",
						"enabled": true,
						"use_output": "default",
						"inputs": [{
							"type": "logs",
							"streams": [{
								"paths": ["/var/log/hello.log"]
							}]
						}]
					}]
				}
			}
		}]
	}
	`
			mux := http.NewServeMux()
			path := fmt.Sprintf("/api/fleet/agents/%s/checkin", agentInfo.AgentID())
			mux.HandleFunc(path, authHandler(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, raw)
			}, withAPIKey))
			return mux
		}, withAPIKey,
		func(t *testing.T, client client.Sender) {
			cmd := pkgfleetapi.NewCheckinCmd(agentInfo, client, defaultCompression)

			request := pkgfleetapi.CheckinRequest{}

			r, _, err := cmd.Execute(ctx, &request)
			require.NoError(t, err)

			var actions Actions
			require.NoError(t, json.Unmarshal(r.Actions, &actions))
			require.Equal(t, 1, len(actions))

			// ActionPolicyChange
			require.Equal(t, "id1", actions[0].ID())
			require.Equal(t, "POLICY_CHANGE", actions[0].Type())
		},
	))

	t.Run("Checkin receives known and unknown action type", withServerWithAuthClient(
		func(t *testing.T) *http.ServeMux {
			raw := `
	{
	    "actions": [
	        {
	            "type": "POLICY_CHANGE",
	            "id": "id1",
	            "data": {
	                "policy": {
	                    "id": "policy-id",
	                    "outputs": {
	                        "default": {
	                            "hosts": "https://localhost:9200"
	                        }
	                    },
						"datasources": [{
							"id": "string",
							"enabled": true,
							"use_output": "default",
							"inputs": [{
								"type": "logs",
								"streams": [{
									"paths": ["/var/log/hello.log"]
								}]
							}]
						}]
	                }
	            }
	        },
	        {
	            "type": "WHAT_TO_DO_WITH_IT",
	            "id": "id2"
	        }
	    ]
	}
	`
			mux := http.NewServeMux()
			path := fmt.Sprintf("/api/fleet/agents/%s/checkin", agentInfo.AgentID())
			mux.HandleFunc(path, authHandler(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, raw)
			}, withAPIKey))
			return mux
		}, withAPIKey,
		func(t *testing.T, client client.Sender) {
			cmd := pkgfleetapi.NewCheckinCmd(agentInfo, client, defaultCompression)

			request := pkgfleetapi.CheckinRequest{}

			r, _, err := cmd.Execute(ctx, &request)
			require.NoError(t, err)

			var actions Actions
			require.NoError(t, json.Unmarshal(r.Actions, &actions))
			require.Equal(t, 2, len(actions))

			// ActionPolicyChange
			require.Equal(t, "id1", actions[0].ID())
			require.Equal(t, "POLICY_CHANGE", actions[0].Type())

			// UnknownAction
			require.Equal(t, "id2", actions[1].ID())
			require.Equal(t, "UNKNOWN", actions[1].Type())
			require.Equal(t, "WHAT_TO_DO_WITH_IT", actions[1].(*ActionUnknown).OriginalType)
		},
	))

	t.Run("When we receive no action with delay", withServerWithAuthClient(
		func(t *testing.T) *http.ServeMux {
			raw := `{ "actions": [] }`
			mux := http.NewServeMux()
			path := fmt.Sprintf("/api/fleet/agents/%s/checkin", agentInfo.AgentID())
			mux.HandleFunc(path, authHandler(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, raw)
			}, withAPIKey))
			return mux
		}, withAPIKey,
		func(t *testing.T, client client.Sender) {
			cmd := pkgfleetapi.NewCheckinCmd(agentInfo, client, defaultCompression)

			request := pkgfleetapi.CheckinRequest{}

			r, _, err := cmd.Execute(ctx, &request)
			require.NoError(t, err)

			var actions Actions
			require.NoError(t, json.Unmarshal(r.Actions, &actions))
			require.Equal(t, 0, len(actions))
		},
	))

	t.Run("Meta are sent", withServerWithAuthClient(
		func(t *testing.T) *http.ServeMux {
			raw := `{"actions": []}`
			mux := http.NewServeMux()
			path := fmt.Sprintf("/api/fleet/agents/%s/checkin", agentInfo.AgentID())
			mux.HandleFunc(path, authHandler(func(w http.ResponseWriter, r *http.Request) {
				type Request struct {
					Metadata *ecsmeta.ECSMeta `json:"local_metadata"`
				}

				var req *Request

				content, err := readMaybeCompressedCheckinBody(r)
				require.NoError(t, err)
				assert.NoError(t, json.Unmarshal(content, &req))
				assert.Equal(t, "linux", req.Metadata.OS.Name)

				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, raw)
			}, withAPIKey))
			return mux
		}, withAPIKey,
		func(t *testing.T, client client.Sender) {
			cmd := pkgfleetapi.NewCheckinCmd(agentInfo, client, defaultCompression)

			request := pkgfleetapi.CheckinRequest{Metadata: testMetadata()}

			r, _, err := cmd.Execute(ctx, &request)
			require.NoError(t, err)

			var actions Actions
			require.NoError(t, json.Unmarshal(r.Actions, &actions))
			require.Equal(t, 0, len(actions))
		},
	))

	t.Run("No meta are sent when not provided", withServerWithAuthClient(
		func(t *testing.T) *http.ServeMux {
			raw := `{"actions": []}`
			mux := http.NewServeMux()
			path := fmt.Sprintf("/api/fleet/agents/%s/checkin", agentInfo.AgentID())
			mux.HandleFunc(path, authHandler(func(w http.ResponseWriter, r *http.Request) {
				type Request struct {
					Metadata *ecsmeta.ECSMeta `json:"local_metadata"`
				}

				var req *Request

				content, err := readMaybeCompressedCheckinBody(r)
				require.NoError(t, err)
				assert.NoError(t, json.Unmarshal(content, &req))
				assert.Nil(t, req.Metadata)

				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, raw)
			}, withAPIKey))
			return mux
		}, withAPIKey,
		func(t *testing.T, client client.Sender) {
			cmd := pkgfleetapi.NewCheckinCmd(agentInfo, client, defaultCompression)

			request := pkgfleetapi.CheckinRequest{}

			r, _, err := cmd.Execute(ctx, &request)
			require.NoError(t, err)

			var actions Actions
			require.NoError(t, json.Unmarshal(r.Actions, &actions))
			require.Equal(t, 0, len(actions))
		},
	))

	t.Run("Headers are sent", withServerWithAuthClient(
		func(t *testing.T) *http.ServeMux {
			raw := `{"actions": []}`
			mux := http.NewServeMux()
			path := fmt.Sprintf("/api/fleet/agents/%s/checkin", agentInfo.AgentID())
			mux.HandleFunc(path, authHandler(func(w http.ResponseWriter, r *http.Request) {
				type Request struct {
					Metadata *ecsmeta.ECSMeta `json:"local_metadata"`
				}

				var req *Request

				content, err := readMaybeCompressedCheckinBody(r)
				require.NoError(t, err)
				assert.NoError(t, json.Unmarshal(content, &req))
				assert.Nil(t, req.Metadata)

				authHeader, ok := r.Header["X-App-Auth"]
				if assert.True(t, ok) && assert.Len(t, authHeader, 1) {
					assert.Equal(t, "auth-token-123", authHeader[0])
				}

				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, raw)
			}, withAPIKey))
			return mux
		}, withAPIKey,
		func(t *testing.T, client client.Sender) {
			cmd := pkgfleetapi.NewCheckinCmd(agentInfo, client, defaultCompression)

			request := pkgfleetapi.CheckinRequest{}

			r, _, err := cmd.Execute(ctx, &request)
			require.NoError(t, err)

			var actions Actions
			require.NoError(t, json.Unmarshal(r.Actions, &actions))
			require.Equal(t, 0, len(actions))
		},
		func(config *remote.Config) {
			config.Headers = map[string]string{
				"X-App-Auth": "auth-token-123",
			}
		},
	))
}

func TestCheckinCompression(t *testing.T) {
	const withAPIKey = "secret"
	const resp = `{"actions": []}`
	agentInfo := &agentinfo{}

	testCases := []struct {
		name           string
		compression    string
		wantCompressed bool
	}{{
		name:           "compression=gzip - request body is compressed",
		compression:    "gzip",
		wantCompressed: true,
	}, {
		name:           "compression=none - request body is not compressed",
		compression:    "none",
		wantCompressed: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, withServerWithAuthClient(
			func(t *testing.T) *http.ServeMux {
				t.Helper()

				mux := http.NewServeMux()
				path := fmt.Sprintf("/api/fleet/agents/%s/checkin", agentInfo.AgentID())
				mux.HandleFunc(path, authHandler(func(w http.ResponseWriter, r *http.Request) {
					checkinPayload, err := readMaybeCompressedCheckinBody(r)
					require.NoError(t, err)

					if tc.wantCompressed {
						assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
					} else {
						assert.Empty(t, r.Header.Get("Content-Encoding"))
					}

					var checkinRequest pkgfleetapi.CheckinRequest
					require.NoError(t, json.Unmarshal(checkinPayload, &checkinRequest))

					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, resp)
				}, withAPIKey))
				return mux
			},
			withAPIKey,
			func(t *testing.T, client client.Sender) {
				cmd := pkgfleetapi.NewCheckinCmd(agentInfo, client, tc.compression)
				_, _, err := cmd.Execute(t.Context(), &pkgfleetapi.CheckinRequest{})
				require.NoError(t, err)
			},
		))
	}
}

func readMaybeCompressedCheckinBody(r *http.Request) ([]byte, error) {
	if r.Header.Get("Content-Encoding") != "gzip" {
		return io.ReadAll(r.Body)
	}

	gzipReader, err := gzip.NewReader(r.Body)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	return io.ReadAll(gzipReader)
}
