// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package store

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestActionStore(t *testing.T) {
	log, _ := logger.New("action_store", false)
	withFile := func(fn func(t *testing.T, file string)) func(*testing.T) {
		return func(t *testing.T) {
			dir, err := ioutil.TempDir("", "action-store")
			require.NoError(t, err)
			defer os.RemoveAll(dir)
			file := filepath.Join(dir, "config.yml")
			fn(t, file)
		}
	}

	t.Run("action returns empty when no action is saved on disk",
		withFile(func(t *testing.T, file string) {
			s := storage.NewDiskStore(file)
			store, err := newActionStore(log, s)
			require.NoError(t, err)
			require.Equal(t, 0, len(store.actions()))
		}))

	t.Run("will discard silently unknown action",
		withFile(func(t *testing.T, file string) {
			actionPolicyChange := &fleetapi.ActionUnknown{
				ActionID: "abc123",
			}

			s := storage.NewDiskStore(file)
			store, err := newActionStore(log, s)
			require.NoError(t, err)

			require.Equal(t, 0, len(store.actions()))
			store.add(actionPolicyChange)
			err = store.save()
			require.NoError(t, err)
			require.Equal(t, 0, len(store.actions()))
		}))

	t.Run("can save to disk known action type",
		withFile(func(t *testing.T, file string) {
			ActionPolicyChange := &fleetapi.ActionPolicyChange{
				ActionID:   "abc123",
				ActionType: "POLICY_CHANGE",
				Policy: map[string]interface{}{
					"hello": "world",
				},
			}

			s := storage.NewDiskStore(file)
			store, err := newActionStore(log, s)
			require.NoError(t, err)

			require.Equal(t, 0, len(store.actions()))
			store.add(ActionPolicyChange)
			err = store.save()
			require.NoError(t, err)
			require.Equal(t, 1, len(store.actions()))

			s = storage.NewDiskStore(file)
			store1, err := newActionStore(log, s)
			require.NoError(t, err)

			actions := store1.actions()
			require.Equal(t, 1, len(actions))

			require.Equal(t, ActionPolicyChange, actions[0])
		}))
}
