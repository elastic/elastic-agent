// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestStoreMigrations(t *testing.T) {
	t.Run("action store file does not exists", func(t *testing.T) {
		ctx := context.Background()
		log, _ := loggertest.New("")

		tempDir := t.TempDir()
		oldActionStorePath := filepath.Join(tempDir, "action_store.yml")
		newStateStorePath := filepath.Join(tempDir, "state_store.yml")

		newStateStore, err := storage.NewEncryptedDiskStore(ctx, newStateStorePath)
		require.NoError(t, err, "failed creating EncryptedDiskStore")

		err = migrateActionStoreToStateStore(log, oldActionStorePath, newStateStore)
		require.NoError(t, err, "migration action store -> state store failed")

		// to load from disk a new store needs to be created, it loads the
		// file to memory during the store creation.
		stateStore, err := NewStateStore(log, newStateStore)
		require.NoError(t, err, "could not load state store")

		assert.Nil(t, stateStore.Action())
		assert.Empty(t, stateStore.Queue())
	})

	t.Run("action store is empty", func(t *testing.T) {
		ctx := context.Background()
		log, _ := loggertest.New("")

		tempDir := t.TempDir()
		oldActionStorePath := filepath.Join(tempDir, "action_store.yml")
		newStateStorePath := filepath.Join(tempDir, "state_store.yml")

		err := os.WriteFile(oldActionStorePath, []byte(""), 0600)
		require.NoError(t, err, "could not create empty action store file")

		newStateStore, err := storage.NewEncryptedDiskStore(ctx, newStateStorePath)
		require.NoError(t, err, "failed creating EncryptedDiskStore")

		err = migrateActionStoreToStateStore(log, oldActionStorePath, newStateStore)
		require.NoError(t, err, "migration action store -> state store failed")

		// to load from disk a new store needs to be created, it loads the
		// file to memory during the store creation.
		stateStore, err := NewStateStore(log, newStateStore)
		require.NoError(t, err, "could not load state store")

		assert.Nil(t, stateStore.Action())
		assert.Empty(t, stateStore.Queue())
	})

	t.Run("action store to YAML state store", func(t *testing.T) {
		tcs := []struct {
			name      string
			storePath string
			want      fleetapi.Action
		}{
			{
				name:      "policy change",
				storePath: "7.17.18-action_store_policy_change.yml",
				want: &fleetapi.ActionPolicyChange{
					ActionID:   "abc123",
					ActionType: "POLICY_CHANGE",
					Data: fleetapi.ActionPolicyChangeData{
						Policy: map[string]any{
							"hello":  "world",
							"phi":    1.618,
							"answer": 42.0,
							"a_map": []any{
								map[string]any{
									"nested_map1": map[string]any{
										"nested_map1_key1": "value1",
										"nested_map1_key2": "value2",
									}},
								map[string]any{
									"nested_map2": map[string]any{
										"nested_map2_key1": "value1",
										"nested_map2_key2": "value2",
									}},
							},
						},
					},
				},
			},
			{
				name:      "unenroll",
				storePath: "7.18.18-action_store_unenroll.yml",
				want: &fleetapi.ActionUnenroll{
					ActionID:   "f450373c-ea62-475c-98c5-26fa174d759f",
					ActionType: "UNENROLL",
					IsDetected: false,
				},
			},
			{
				name:      "unsupported",
				storePath: "7.18.18-action_store_unknown.yml",
				want:      nil,
			},
			{
				name:      "empty store",
				storePath: "7.17.18-action_store_empty.yml",
				want:      nil,
			},
		}

		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				log, _ := loggertest.New("")

				tempDir := t.TempDir()
				vaultPath := createAgentVaultAndSecret(t, ctx, tempDir)

				goldenActionStore, err := os.ReadFile(
					filepath.Join("testdata", tc.storePath))
				require.NoError(t, err, "could not read action store golden file")

				oldActionStorePath := filepath.Join(tempDir, "action_store.yml")
				err = os.WriteFile(oldActionStorePath, goldenActionStore, 0666)
				require.NoError(t, err, "could not copy action store golden file")

				newStateStorePath := filepath.Join(tempDir, "state_store.yaml")
				newStateStore, err := storage.NewEncryptedDiskStore(ctx, newStateStorePath,
					storage.WithVaultPath(vaultPath))
				require.NoError(t, err, "failed creating EncryptedDiskStore")

				err = migrateActionStoreToStateStore(log, oldActionStorePath, newStateStore)
				require.NoError(t, err, "migration action store -> state store failed")

				// to load from disk a new store needs to be created, it loads the file
				// to memory during the store creation.
				stateStore, err := NewStateStore(log, newStateStore)
				require.NoError(t, err, "could not create state store")

				got := stateStore.Action()

				assert.Equalf(t, tc.want, got,
					"loaded action differs from action on the old action store")
				assert.Empty(t, stateStore.Queue(),
					"queue should be empty, old action store did not have a queue")
			})
		}
	})

	t.Run("YAML state store to JSON state store", func(t *testing.T) {
		tests := []struct {
			name      string
			yamlStore string
			wantState state
		}{
			{
				name:      "ActionPolicyChange",
				yamlStore: "8.0.0-action_policy_change.yml",
				wantState: state{
					Version: "1",
					ActionSerializer: actionSerializer{Action: &fleetapi.ActionPolicyChange{
						ActionID:   "policy:POLICY-ID:1:1",
						ActionType: "POLICY_CHANGE",
						Data: fleetapi.ActionPolicyChangeData{
							Policy: map[string]any{
								"hello":  "world",
								"phi":    1.618,
								"answer": 42.0,
								"a_map": []any{
									map[string]any{
										"nested_map1": map[string]any{
											"nested_map1_key1": "value1",
											"nested_map1_key2": "value2",
										}},
									map[string]any{
										"nested_map2": map[string]any{
											"nested_map2_key1": "value1",
											"nested_map2_key2": "value2",
										}},
								},
							},
						},
					}},
					AckToken: "czlV93YBwdkt5lYhBY7S",
					Queue: actionQueue{&fleetapi.ActionUpgrade{
						ActionID:         "action1",
						ActionType:       "UPGRADE",
						ActionStartTime:  "2024-02-19T17:48:40Z",
						ActionExpiration: "2025-02-19T17:48:40Z",
						Data: fleetapi.ActionUpgradeData{
							Version:   "1.2.3",
							SourceURI: "https://example.com",
							Retry:     1,
						},
						Signed: nil,
						Err:    nil,
					},
						&fleetapi.ActionUpgrade{
							ActionID:         "action2",
							ActionType:       "UPGRADE",
							ActionStartTime:  "2024-02-19T17:48:40Z",
							ActionExpiration: "2025-02-19T17:48:40Z",
							Data: fleetapi.ActionUpgradeData{
								Version:   "1.2.3",
								SourceURI: "https://example.com",
								Retry:     1,
							},
							Signed: nil,
							Err:    nil,
						}},
				},
			},
			{
				name:      "ActionUnenroll",
				yamlStore: "8.0.0-action_unenroll.yml",
				wantState: state{
					Version: "1",
					ActionSerializer: actionSerializer{Action: &fleetapi.ActionUnenroll{
						ActionID:   "abc123",
						ActionType: "UNENROLL",
						IsDetected: true,
						Signed:     nil,
					}},
					AckToken: "czlV93YBwdkt5lYhBY7S",
					Queue: actionQueue{&fleetapi.ActionUpgrade{
						ActionID:         "action1",
						ActionType:       "UPGRADE",
						ActionStartTime:  "2024-02-19T17:48:40Z",
						ActionExpiration: "2025-02-19T17:48:40Z",
						Data: fleetapi.ActionUpgradeData{
							Version:   "1.2.3",
							SourceURI: "https://example.com",
							Retry:     1,
						},
						Signed: nil,
						Err:    nil,
					},
						&fleetapi.ActionUpgrade{
							ActionID:         "action2",
							ActionType:       "UPGRADE",
							ActionStartTime:  "2024-02-19T17:48:40Z",
							ActionExpiration: "2025-02-19T17:48:40Z",
							Data: fleetapi.ActionUpgradeData{
								Version:   "1.2.3",
								SourceURI: "https://example.com",
								Retry:     1,
							},
							Signed: nil,
							Err:    nil,
						}},
				},
			},
			{
				name:      "unknown",
				yamlStore: "8.0.0-action_unknown.yml",
				wantState: state{
					Version:          "1",
					ActionSerializer: actionSerializer{Action: nil},
					AckToken:         "czlV93YBwdkt5lYhBY7S",
					Queue:            nil,
				},
			},
			{
				name:      "empty store",
				yamlStore: "8.0.0-empty.yml",
				wantState: state{
					Version:          "1",
					ActionSerializer: actionSerializer{Action: nil},
					AckToken:         "",
					Queue:            nil,
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctx := context.Background()
				log, _ := loggertest.New("")

				tempDir := t.TempDir()
				vaultPath := createAgentVaultAndSecret(t, ctx, tempDir)

				yamlStorePlain, err := os.ReadFile(
					filepath.Join("testdata", tt.yamlStore))
				require.NoError(t, err, "could not read action store golden file")

				encDiskStorePath := filepath.Join(tempDir, "store.enc")
				encDiskStore, err := storage.NewEncryptedDiskStore(ctx, encDiskStorePath, storage.WithVaultPath(vaultPath))
				require.NoError(t, err, "failed creating EncryptedDiskStore")

				err = encDiskStore.Save(bytes.NewBuffer(yamlStorePlain))
				require.NoError(t, err, "failed saving copy of golden files on an EncryptedDiskStore")

				err = migrateYAMLStateStoreToStateStoreV1(log, encDiskStore)
				require.NoError(t, err, "YAML state store -> JSON state store failed")

				// Load migrated store from disk
				stateStore, err := NewStateStore(log, encDiskStore)
				require.NoError(t, err, "could not load store from disk")

				assert.Equal(t, tt.wantState, stateStore.state)
			})
		}
	})

	t.Run("YAML state store containing an ActionPolicyChange to JSON state store",
		func(t *testing.T) {
			ctx := context.Background()
			log, _ := loggertest.New("")

			want := state{
				Version: "1",
				ActionSerializer: actionSerializer{Action: &fleetapi.ActionPolicyChange{
					ActionID:   "policy:POLICY-ID:1:1",
					ActionType: "POLICY_CHANGE",
					Data: fleetapi.ActionPolicyChangeData{
						Policy: map[string]any{
							"hello":  "world",
							"phi":    1.618,
							"answer": 42.0,
							"a_map": []any{
								map[string]any{
									"nested_map1": map[string]any{
										"nested_map1_key1": "value1",
										"nested_map1_key2": "value2",
									}},
								map[string]any{
									"nested_map2": map[string]any{
										"nested_map2_key1": "value1",
										"nested_map2_key2": "value2",
									}},
							},
						},
					},
				}},
				AckToken: "czlV93YBwdkt5lYhBY7S",
				Queue: actionQueue{&fleetapi.ActionUpgrade{
					ActionID:         "action1",
					ActionType:       "UPGRADE",
					ActionStartTime:  "2024-02-19T17:48:40Z",
					ActionExpiration: "2025-02-19T17:48:40Z",
					Data: fleetapi.ActionUpgradeData{
						Version:   "1.2.3",
						SourceURI: "https://example.com",
						Retry:     1,
					},
					Signed: nil,
					Err:    nil,
				},
					&fleetapi.ActionUpgrade{
						ActionID:         "action2",
						ActionType:       "UPGRADE",
						ActionStartTime:  "2024-02-19T17:48:40Z",
						ActionExpiration: "2025-02-19T17:48:40Z",
						Data: fleetapi.ActionUpgradeData{
							Version:   "1.2.3",
							SourceURI: "https://example.com",
							Retry:     1,
						},
						Signed: nil,
						Err:    nil,
					}},
			}

			tempDir := t.TempDir()
			vaultPath := createAgentVaultAndSecret(t, ctx, tempDir)

			yamlStorePlain, err := os.ReadFile(
				filepath.Join("testdata", "8.0.0-action_policy_change.yml"))
			require.NoError(t, err, "could not read action store golden file")

			encDiskStorePath := filepath.Join(tempDir, "store.enc")
			encDiskStore, err := storage.NewEncryptedDiskStore(ctx, encDiskStorePath,
				storage.WithVaultPath(vaultPath))
			require.NoError(t, err, "failed creating EncryptedDiskStore")

			err = encDiskStore.Save(bytes.NewBuffer(yamlStorePlain))
			require.NoError(t, err,
				"failed saving copy of golden files on an EncryptedDiskStore")

			err = migrateYAMLStateStoreToStateStoreV1(log, encDiskStore)
			require.NoError(t, err, "YAML state store -> JSON state store failed")

			// Load migrated store from disk
			stateStore, err := NewStateStore(log, encDiskStore)
			require.NoError(t, err, "could not load store from disk")

			assert.Equal(t, want, stateStore.state)
		})

	t.Run("YAML state store when JSON state store exists", func(t *testing.T) {
		log, _ := loggertest.New("")

		ctx := context.Background()

		want := state{
			Version: "1",
			ActionSerializer: actionSerializer{Action: &fleetapi.ActionPolicyChange{
				ActionID:   "abc123",
				ActionType: "POLICY_CHANGE",
				Data: fleetapi.ActionPolicyChangeData{
					Policy: map[string]any{
						"hello":  "world",
						"phi":    1.618,
						"answer": 42.0,
						"a_map": []any{
							map[string]any{
								"nested_map1": map[string]any{
									"nested_map1_key1": "value1",
									"nested_map1_key2": "value2",
								}},
							map[string]any{
								"nested_map2": map[string]any{
									"nested_map2_key1": "value1",
									"nested_map2_key2": "value2",
								}},
						},
					},
				},
			}},
			AckToken: "czlV93YBwdkt5lYhBY7S",
			Queue: actionQueue{&fleetapi.ActionUpgrade{
				ActionID:         "action1",
				ActionType:       "UPGRADE",
				ActionStartTime:  "2024-02-19T17:48:40Z",
				ActionExpiration: "2025-02-19T17:48:40Z",
				Data: fleetapi.ActionUpgradeData{
					Version:   "1.2.3",
					SourceURI: "https://example.com",
					Retry:     1,
				},
				Signed: nil,
				Err:    nil,
			},
				&fleetapi.ActionUpgrade{
					ActionID:         "action2",
					ActionType:       "UPGRADE",
					ActionStartTime:  "2024-02-19T17:48:40Z",
					ActionExpiration: "2025-02-19T17:48:40Z",
					Data: fleetapi.ActionUpgradeData{
						Version:   "1.2.3",
						SourceURI: "https://example.com",
						Retry:     1,
					},
					Signed: nil,
					Err:    nil,
				}},
		}

		tempDir := t.TempDir()
		vaultPath := createAgentVaultAndSecret(t, ctx, tempDir)

		stateStorePath := filepath.Join(tempDir, "store.enc")
		endDiskStore, err := storage.NewEncryptedDiskStore(ctx, stateStorePath,
			storage.WithVaultPath(vaultPath))
		require.NoError(t, err, "failed creating EncryptedDiskStore")

		// Create and save a JSON state store
		stateStore, err := NewStateStore(log, endDiskStore)
		require.NoError(t, err, "could not create state store")
		stateStore.SetAckToken(want.AckToken)
		stateStore.SetAction(want.ActionSerializer.Action)
		stateStore.SetQueue(want.Queue)
		err = stateStore.Save()
		require.NoError(t, err, "state store save filed")

		// Try to migrate an existing JSON store
		err = migrateYAMLStateStoreToStateStoreV1(log, endDiskStore)
		require.NoError(t, err, "YAML state store -> JSON state store failed")

		// Load migrated store from disk
		stateStore, err = NewStateStore(log, endDiskStore)
		require.NoError(t, err, "could not load store from disk")

		assert.Equal(t, want, stateStore.state)
	})

	t.Run("newStateStoreWithMigration", func(t *testing.T) {
		t.Run("action store exists", func(t *testing.T) {
			ctx := context.Background()
			log, _ := loggertest.New("")

			want := &fleetapi.ActionPolicyChange{
				ActionID:   "abc123",
				ActionType: "POLICY_CHANGE",
				Data: fleetapi.ActionPolicyChangeData{
					Policy: map[string]any{
						"hello":  "world",
						"phi":    1.618,
						"answer": 42.0,
						"a_map": []any{
							map[string]any{
								"nested_map1": map[string]any{
									"nested_map1_key1": "value1",
									"nested_map1_key2": "value2",
								}},
							map[string]any{
								"nested_map2": map[string]any{
									"nested_map2_key1": "value1",
									"nested_map2_key2": "value2",
								}},
						},
					},
				},
			}

			tempDir := t.TempDir()
			vaultPath := createAgentVaultAndSecret(t, ctx, tempDir)

			goldenActionStore, err := os.ReadFile(
				filepath.Join("testdata", "7.17.18-action_store_policy_change.yml"))
			require.NoError(t, err, "could not read action store golden file")

			oldActionStorePath := filepath.Join(tempDir, "action_store.yml")
			err = os.WriteFile(oldActionStorePath, goldenActionStore, 0666)
			require.NoError(t, err, "could not copy action store golden file")

			newStateStorePath := filepath.Join(tempDir, "state_store.yaml")
			newStateStore, err := storage.NewEncryptedDiskStore(ctx, newStateStorePath,
				storage.WithVaultPath(vaultPath))
			require.NoError(t, err, "failed creating EncryptedDiskStore")

			stateStore, err := newStateStoreWithMigration(log, oldActionStorePath, newStateStore)
			require.NoError(t, err, "newStateStoreWithMigration failed")

			got := stateStore.Action()
			assert.Equalf(t, want, got,
				"loaded action differs from action on the old action store")
			assert.Empty(t, stateStore.Queue(),
				"queue should be empty, old action store did not have a queue")
			assert.NoFileExists(t, oldActionStorePath,
				"old action store should have been deleted upon successful migration")
		})

		t.Run("YAML state store to JSON state store", func(t *testing.T) {
			ctx := context.Background()
			log, _ := loggertest.New("")

			want := state{
				Version: "1",
				ActionSerializer: actionSerializer{Action: &fleetapi.ActionPolicyChange{
					ActionID:   "policy:POLICY-ID:1:1",
					ActionType: "POLICY_CHANGE",
					Data: fleetapi.ActionPolicyChangeData{
						Policy: map[string]any{
							"hello":  "world",
							"phi":    1.618,
							"answer": 42.0,
							"a_map": []any{
								map[string]any{
									"nested_map1": map[string]any{
										"nested_map1_key1": "value1",
										"nested_map1_key2": "value2",
									}},
								map[string]any{
									"nested_map2": map[string]any{
										"nested_map2_key1": "value1",
										"nested_map2_key2": "value2",
									}},
							},
						},
					},
				}},
				AckToken: "czlV93YBwdkt5lYhBY7S",
				Queue: actionQueue{&fleetapi.ActionUpgrade{
					ActionID:         "action1",
					ActionType:       "UPGRADE",
					ActionStartTime:  "2024-02-19T17:48:40Z",
					ActionExpiration: "2025-02-19T17:48:40Z",
					Data: fleetapi.ActionUpgradeData{
						Version:   "1.2.3",
						SourceURI: "https://example.com",
						Retry:     1,
					},
					Signed: nil,
					Err:    nil,
				},
					&fleetapi.ActionUpgrade{
						ActionID:         "action2",
						ActionType:       "UPGRADE",
						ActionStartTime:  "2024-02-19T17:48:40Z",
						ActionExpiration: "2025-02-19T17:48:40Z",
						Data: fleetapi.ActionUpgradeData{
							Version:   "1.2.3",
							SourceURI: "https://example.com",
							Retry:     1,
						},
						Signed: nil,
						Err:    nil,
					}},
			}

			tempDir := t.TempDir()
			vaultPath := createAgentVaultAndSecret(t, ctx, tempDir)

			yamlStorePlain, err := os.ReadFile(
				filepath.Join("testdata", "8.0.0-action_policy_change.yml"))
			require.NoError(t, err, "could not read action store golden file")

			yamlStoreEncPath := filepath.Join(tempDir, "yaml_store.enc")
			yamlStoreEnc, err := storage.NewEncryptedDiskStore(ctx, yamlStoreEncPath,
				storage.WithVaultPath(vaultPath))
			require.NoError(t, err, "failed creating EncryptedDiskStore")

			err = yamlStoreEnc.Save(bytes.NewBuffer(yamlStorePlain))
			require.NoError(t, err,
				"failed saving copy of golden files on an EncryptedDiskStore")

			stateStore, err := newStateStoreWithMigration(log, filepath.Join(tempDir, "non-existing-action-store.yaml"), yamlStoreEnc)
			require.NoError(t, err, "newStateStoreWithMigration failed")

			assert.Equal(t, want, stateStore.state)
		})

		t.Run("up to date store, no migration needed", func(t *testing.T) {
			log, _ := loggertest.New("")

			ctx := context.Background()

			want := state{
				Version: "1",
				ActionSerializer: actionSerializer{Action: &fleetapi.ActionPolicyChange{
					ActionID:   "abc123",
					ActionType: "POLICY_CHANGE",
					Data: fleetapi.ActionPolicyChangeData{
						Policy: map[string]any{
							"hello":  "world",
							"phi":    1.618,
							"answer": 42.0,
							"a_map": []any{
								map[string]any{
									"nested_map1": map[string]any{
										"nested_map1_key1": "value1",
										"nested_map1_key2": "value2",
									}},
								map[string]any{
									"nested_map2": map[string]any{
										"nested_map2_key1": "value1",
										"nested_map2_key2": "value2",
									}},
							},
						},
					},
				}},
				AckToken: "czlV93YBwdkt5lYhBY7S",
				Queue: actionQueue{&fleetapi.ActionUpgrade{
					ActionID:         "action1",
					ActionType:       "UPGRADE",
					ActionStartTime:  "2024-02-19T17:48:40Z",
					ActionExpiration: "2025-02-19T17:48:40Z",
					Data: fleetapi.ActionUpgradeData{
						Version:   "1.2.3",
						SourceURI: "https://example.com",
						Retry:     1,
					},
					Signed: nil,
					Err:    nil,
				},
					&fleetapi.ActionUpgrade{
						ActionID:         "action2",
						ActionType:       "UPGRADE",
						ActionStartTime:  "2024-02-19T17:48:40Z",
						ActionExpiration: "2025-02-19T17:48:40Z",
						Data: fleetapi.ActionUpgradeData{
							Version:   "1.2.3",
							SourceURI: "https://example.com",
							Retry:     1,
						},
						Signed: nil,
						Err:    nil,
					}},
			}

			tempDir := t.TempDir()
			vaultPath := createAgentVaultAndSecret(t, ctx, tempDir)

			stateStorePath := filepath.Join(tempDir, "store.enc")
			endDiskStore, err := storage.NewEncryptedDiskStore(ctx, stateStorePath,
				storage.WithVaultPath(vaultPath))
			require.NoError(t, err, "failed creating EncryptedDiskStore")

			// Create and save a JSON state store
			stateStore, err := NewStateStore(log, endDiskStore)
			require.NoError(t, err, "could not create state store")
			stateStore.SetAckToken(want.AckToken)
			stateStore.SetAction(want.ActionSerializer.Action)
			stateStore.SetQueue(want.Queue)
			err = stateStore.Save()
			require.NoError(t, err, "state store save filed")

			stateStore, err = newStateStoreWithMigration(log, filepath.Join(tempDir, "non-existing-action-store.yaml"), endDiskStore)
			require.NoError(t, err, "newStateStoreWithMigration failed")

			assert.Equal(t, want, stateStore.state)
		})

		t.Run("no store exists", func(t *testing.T) {
			ctx := context.Background()
			log, _ := loggertest.New("")

			tempDir := t.TempDir()
			paths.SetConfig(tempDir)
			vaultPath := createAgentVaultAndSecret(t, ctx, tempDir)

			stateStorePath := filepath.Join(tempDir, "store.enc")
			endDiskStore, err := storage.NewEncryptedDiskStore(ctx, stateStorePath,
				storage.WithVaultPath(vaultPath))
			require.NoError(t, err, "failed creating EncryptedDiskStore")

			got, err := newStateStoreWithMigration(log, filepath.Join(tempDir, "non-existing-action-store.yaml"), endDiskStore)
			require.NoError(t, err, "newStateStoreWithMigration failed")

			assert.Nil(t, got.Action(),
				"no action should have been loaded")
			assert.Empty(t, got.Queue(), "action queue should be empty")
			assert.Empty(t, got.AckToken(),
				"no AckToken should have been loaded")
		})
	})

	t.Run("NewStateStoreWithMigration", func(t *testing.T) {
		t.Run("return error if action store is invalid", func(t *testing.T) {
			ctx := context.Background()
			log, _ := loggertest.New("")

			tempDir := t.TempDir()
			oldActionStorePath := filepath.Join(tempDir, "action_store.yml")
			newStateStorePath := filepath.Join(tempDir, "state_store.enc")

			err := os.WriteFile(oldActionStorePath, []byte("&"), 0600)
			require.NoError(t, err, "could not create empty action store file")

			s, err := NewStateStoreWithMigration(ctx, log, oldActionStorePath, newStateStorePath)

			assert.Error(t, err, "when the action store migration fails, it should return an error")
			assert.FileExists(t, oldActionStorePath, "invalid action store should NOT have been deleted")
			assert.Nil(t, s, "state store should be nil when an error is returned")
		})

		t.Run("returns error if YAML state store is invalid", func(t *testing.T) {
			ctx := context.Background()
			log, _ := loggertest.New("")

			tempDir := t.TempDir()
			paths.SetConfig(tempDir)
			createAgentVaultAndSecret(t, ctx, tempDir)
			oldActionStorePath := filepath.Join(tempDir, "action_store.yml")
			newStateStorePath := filepath.Join(tempDir, "state_store.enc")

			err := os.WriteFile(newStateStorePath, []byte("&"), 0600)
			require.NoError(t, err, "could not create empty action store file")

			s, err := NewStateStoreWithMigration(ctx, log, oldActionStorePath, newStateStorePath)
			assert.ErrorContains(t, err, "failed migrating YAML store JSON store")
			assert.Nil(t, s, "state store should be nil when an error ir returned")
		})

		t.Run("returns error if state store V1 (JSON) is invalid", func(t *testing.T) {
			// As YAML 1.2 is a superset of JSON, the migration code checks first
			// if the content is a valid JSON, if it's, no migration happens.
			// If the content is invalid, then it tries to migrate from the YAML store.
			// Therefore, the error is regarding invalid YAML and not invalid JSON.

			ctx := context.Background()
			log, _ := loggertest.New("")

			tempDir := t.TempDir()
			paths.SetConfig(tempDir)
			createAgentVaultAndSecret(t, ctx, tempDir)
			oldActionStorePath := filepath.Join(tempDir, "action_store.yml")
			newStateStorePath := filepath.Join(tempDir, "state_store.enc")

			err := os.WriteFile(newStateStorePath, []byte("}"), 0600)
			require.NoError(t, err, "could not create empty action store file")

			s, err := NewStateStoreWithMigration(ctx, log, oldActionStorePath, newStateStorePath)
			assert.ErrorContains(t, err, "failed migrating YAML store JSON store",
				"As YAML 1.2 is a superset of JSON, the migration code checks first if the content is a valid JSON, if it's, no migration happens.\nIf the content is invalid, then it tries to migrate from the YAML store.\nTherefore, the error is regarding invalid YAML and not invalid JSON.")
			assert.Nil(t, s, "state store should be nil when an error ir returned")
		})
	})
}
