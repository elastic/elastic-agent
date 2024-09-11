// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
)

func TestEnroll(t *testing.T) {
	t.Run("Successful enroll", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/fleet/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Type", "application/json")

				// Assert Enrollment Token.
				require.Equal(t, "ApiKey my-enrollment-api-key", r.Header.Get("Authorization"))

				decoder := json.NewDecoder(r.Body)
				defer r.Body.Close()

				req := &EnrollRequest{}
				err := decoder.Decode(req)
				require.NoError(t, err)

				require.Equal(t, PermanentEnroll, req.Type)
				require.Equal(t, make(map[string]interface{}), req.Metadata.UserProvided)
				require.Equal(t, "linux", req.Metadata.Local.OS.Name)

				response := &EnrollResponse{
					Action: "created",
					Item: EnrollItemResponse{
						ID:                   "a4937110-e53e-11e9-934f-47a8e38a522c",
						Active:               true,
						PolicyID:             "default",
						Type:                 PermanentEnroll,
						EnrolledAt:           time.Now(),
						UserProvidedMetadata: make(map[string]interface{}),
						LocalMetadata:        make(map[string]interface{}),
						AccessAPIKey:         "my-access-api-key",
					},
				}

				b, err := json.Marshal(response)
				require.NoError(t, err)

				_, err = w.Write(b)
				assert.NoError(t, err)
			})
			return mux
		}, func(t *testing.T, host string) {
			cfg := config.MustNewConfigFrom(map[string]interface{}{
				"host": host,
			})

			client, err := remote.NewWithRawConfig(nil, cfg, nil)
			require.NoError(t, err)

			req := &EnrollRequest{
				Type:         PermanentEnroll,
				EnrollAPIKey: "my-enrollment-api-key",
				Metadata: Metadata{
					Local:        testMetadata(),
					UserProvided: make(map[string]interface{}),
				},
			}

			cmd := &EnrollCmd{client: client}
			resp, err := cmd.Execute(context.Background(), req)
			require.NoError(t, err)

			require.Equal(t, "my-access-api-key", resp.Item.AccessAPIKey)
			require.Equal(t, "created", resp.Action)
		},
	))

	t.Run("Raise back any server errors", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/fleet/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte(`{"statusCode": 500, "error":"Something is really bad here"}`))
				assert.NoError(t, err)
			})
			return mux
		}, func(t *testing.T, host string) {
			cfg := config.MustNewConfigFrom(map[string]interface{}{
				"host": host,
			})

			client, err := remote.NewWithRawConfig(nil, cfg, nil)
			require.NoError(t, err)

			req := &EnrollRequest{
				Type:         PermanentEnroll,
				EnrollAPIKey: "my-enrollment-api-key",
				Metadata: Metadata{
					Local:        testMetadata(),
					UserProvided: make(map[string]interface{}),
				},
			}

			cmd := &EnrollCmd{client: client}
			_, err = cmd.Execute(context.Background(), req)
			require.Error(t, err)

			require.True(t, strings.Index(err.Error(), "500") > 0)
			require.True(t, strings.Index(err.Error(), "Something is really bad here") > 0)
		},
	))

	t.Run("Returns temporary server errors", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/fleet/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte(`{"statusCode": 503, "error":"maintenance"}`))
				assert.NoError(t, err)
			})
			return mux
		}, func(t *testing.T, host string) {
			cfg := config.MustNewConfigFrom(map[string]interface{}{
				"host": host,
			})

			client, err := remote.NewWithRawConfig(nil, cfg, nil)
			require.NoError(t, err)

			req := &EnrollRequest{
				Type:         PermanentEnroll,
				EnrollAPIKey: "my-enrollment-api-key",
				Metadata: Metadata{
					Local:        testMetadata(),
					UserProvided: make(map[string]interface{}),
				},
			}

			cmd := &EnrollCmd{client: client}
			_, err = cmd.Execute(context.Background(), req)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrTemporaryServerError)
			require.Contains(t, err.Error(), "code 503")
		},
	))
}

func testMetadata() *info.ECSMeta {
	return &info.ECSMeta{
		OS: &info.SystemECSMeta{
			Name: "linux",
		},
	}
}
