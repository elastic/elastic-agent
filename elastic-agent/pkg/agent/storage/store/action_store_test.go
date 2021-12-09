// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package store

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/storage"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/fleetapi"
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
			store, err := NewActionStore(log, s)
			require.NoError(t, err)
			require.Equal(t, 0, len(store.Actions()))
		}))

	t.Run("will discard silently unknown action",
		withFile(func(t *testing.T, file string) {
			actionPolicyChange := &fleetapi.ActionUnknown{
				ActionID: "abc123",
			}

			s := storage.NewDiskStore(file)
			store, err := NewActionStore(log, s)
			require.NoError(t, err)

			require.Equal(t, 0, len(store.Actions()))
			store.Add(actionPolicyChange)
			err = store.Save()
			require.NoError(t, err)
			require.Equal(t, 0, len(store.Actions()))
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
			store, err := NewActionStore(log, s)
			require.NoError(t, err)

			require.Equal(t, 0, len(store.Actions()))
			store.Add(ActionPolicyChange)
			err = store.Save()
			require.NoError(t, err)
			require.Equal(t, 1, len(store.Actions()))

			s = storage.NewDiskStore(file)
			store1, err := NewActionStore(log, s)
			require.NoError(t, err)

			actions := store1.Actions()
			require.Equal(t, 1, len(actions))

			require.Equal(t, ActionPolicyChange, actions[0])
		}))
}
