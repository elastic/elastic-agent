// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package store

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

type wrongAction struct{}

func (wrongAction) ID() string                  { return "" }
func (wrongAction) Type() string                { return "" }
func (wrongAction) String() string              { return "" }
func (wrongAction) AckEvent() fleetapi.AckEvent { return fleetapi.AckEvent{} }

func TestStateStore(t *testing.T) {
	t.Run("ack token", func(t *testing.T) {
		runTestStateStore(t, "czlV93YBwdkt5lYhBY7S")
	})

	t.Run("no ack token", func(t *testing.T) {
		runTestStateStore(t, "")
	})
}

func createAgentVaultAndSecret(t *testing.T, ctx context.Context, tempDir string) string {
	vaultPath := filepath.Join(tempDir, "vault")

	err := os.MkdirAll(vaultPath, 0o750)
	require.NoError(t, err,
		"could not create directory for the agent's vault")

	_, err = vault.New(ctx,
		vault.WithVaultPath(vaultPath),
		vault.WithUnprivileged(true))
	require.NoError(t, err, "could not create agent's vault")
	err = secret.CreateAgentSecret(
		context.Background(),
		vault.WithVaultPath(vaultPath),
		vault.WithUnprivileged(true))
	require.NoError(t, err, "could not create agent secret")

	return vaultPath
}

func runTestStateStore(t *testing.T, ackToken string) {
	log, _ := loggertest.New("state_store")

	t.Run("SetAction corner case", func(t *testing.T) {

		t.Run("nil fleetapi.Action", func(t *testing.T) {
			var action fleetapi.Action

			storePath := filepath.Join(t.TempDir(), "state.json")
			s, err := storage.NewDiskStore(storePath)
			require.NoError(t, err, "failed creating DiskStore")

			store, err := NewStateStore(log, s)
			require.NoError(t, err)
			require.Nil(t, store.Action())

			store.SetAction(action)
			store.SetAckToken(ackToken)
			err = store.Save()
			require.NoError(t, err)

			assert.Empty(t, store.Action())
			assert.Empty(t, store.Queue())
			assert.Equal(t, ackToken, store.AckToken())
		})

		t.Run("nil concrete and accepted action", func(t *testing.T) {
			var actionUnenroll *fleetapi.ActionUnenroll
			actionPolicyChange := &fleetapi.ActionPolicyChange{
				ActionID: "abc123",
			}

			storePath := filepath.Join(t.TempDir(), "state.json")
			s, err := storage.NewDiskStore(storePath)
			require.NoError(t, err, "failed creating DiskStore")

			store, err := NewStateStore(log, s)
			require.NoError(t, err)
			require.Nil(t, store.Action())

			// 1st set an action
			store.SetAction(actionPolicyChange)
			store.SetAckToken(ackToken)
			err = store.Save()
			require.NoError(t, err)

			// then try to set a nil action
			store.SetAction(actionUnenroll)
			store.SetAckToken(ackToken)
			err = store.Save()
			require.NoError(t, err)

			assert.Equal(t, actionPolicyChange, store.Action())
			assert.Empty(t, store.Queue())
			assert.Equal(t, ackToken, store.AckToken())
		})

		t.Run("nil concrete and ignored action", func(t *testing.T) {
			var actionUnknown *fleetapi.ActionUnknown
			actionPolicyChange := &fleetapi.ActionPolicyChange{
				ActionID: "abc123",
			}

			storePath := filepath.Join(t.TempDir(), "state.json")
			s, err := storage.NewDiskStore(storePath)
			require.NoError(t, err, "failed creating DiskStore")

			store, err := NewStateStore(log, s)
			require.NoError(t, err)
			require.Nil(t, store.Action())

			// 1st set an action
			store.SetAction(actionPolicyChange)
			store.SetAckToken(ackToken)
			err = store.Save()
			require.NoError(t, err)

			// then try to set a nil action
			store.SetAction(actionUnknown)
			store.SetAckToken(ackToken)
			err = store.Save()
			require.NoError(t, err)

			assert.Equal(t, actionPolicyChange, store.Action())
			assert.Empty(t, store.Queue())
			assert.Equal(t, ackToken, store.AckToken())
		})
	})

	t.Run("store is not dirty on successful save", func(t *testing.T) {
		storePath := filepath.Join(t.TempDir(), "state.json")
		s, err := storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err := NewStateStore(log, s)
		require.NoError(t, err)

		store.dirty = true
		err = store.Save()
		require.NoError(t, err, "unexpected error when saving")

		assert.False(t, store.dirty,
			"the store should not be marked as dirty")
	})

	t.Run("store is dirty when save fails", func(t *testing.T) {
		storePath := filepath.Join(t.TempDir(), "state.json")
		s, err := storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err := NewStateStore(log, s)
		require.NoError(t, err)

		store.dirty = true
		store.state.ActionSerializer.Action = fleetapi.NewAction(fleetapi.ActionTypeUnknown)
		err = store.Save()
		require.Error(t, err, "expected an error when saving store with invalid state")

		assert.True(t, store.dirty,
			"the store should be kept dirty when save fails")
	})

	t.Run("action returns empty when no action is saved on disk", func(t *testing.T) {
		storePath := filepath.Join(t.TempDir(), "state.json")
		s, err := storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err := NewStateStore(log, s)
		require.NoError(t, err)
		require.Empty(t, store.Action())
		require.Empty(t, store.Queue())
	})

	t.Run("will discard silently unknown action", func(t *testing.T) {
		actionPolicyChange := &fleetapi.ActionUnknown{
			ActionID: "abc123",
		}

		storePath := filepath.Join(t.TempDir(), "state.json")
		s, err := storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err := NewStateStore(log, s)
		require.NoError(t, err)

		require.Nil(t, store.Action())
		store.SetAction(actionPolicyChange)
		store.SetAckToken(ackToken)
		err = store.Save()
		require.NoError(t, err)
		require.Empty(t, store.Action())
		require.Empty(t, store.Queue())
		require.Equal(t, ackToken, store.AckToken())
	})

	t.Run("can save to disk ActionPolicyChange", func(t *testing.T) {
		ActionPolicyChange := &fleetapi.ActionPolicyChange{
			ActionID:   "abc123",
			ActionType: "POLICY_CHANGE",
			Data: fleetapi.ActionPolicyChangeData{
				Policy: map[string]interface{}{
					"hello": "world",
				}},
		}

		storePath := filepath.Join(t.TempDir(), "state.json")
		s, err := storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err := NewStateStore(log, s)
		require.NoError(t, err)

		require.Empty(t, store.Action())
		require.Empty(t, store.Queue())
		store.SetAction(ActionPolicyChange)
		store.SetAckToken(ackToken)
		err = store.Save()
		require.NoError(t, err)
		require.NotNil(t, store.Action(), "store should have an action stored")
		require.Empty(t, store.Queue())
		require.Equal(t, ackToken, store.AckToken())

		s, err = storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store1, err := NewStateStore(log, s)
		require.NoError(t, err)

		action := store1.Action()
		require.NotNil(t, action, "store should have an action stored")
		require.Empty(t, store1.Queue())

		require.Equal(t, ActionPolicyChange, action)
		require.Equal(t, ackToken, store.AckToken())
	})

	t.Run("can save to disk ActionUnenroll", func(t *testing.T) {
		want := &fleetapi.ActionUnenroll{
			ActionID:   "abc123",
			ActionType: "UNENROLL",
		}

		storePath := filepath.Join(t.TempDir(), "state.json")
		s, err := storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err := NewStateStore(log, s)
		require.NoError(t, err)

		require.Empty(t, store.Action())
		require.Empty(t, store.Queue())
		store.SetAction(want)
		store.SetAckToken(ackToken)
		err = store.Save()
		require.NoError(t, err)
		require.NotNil(t, store.Action(), "store should have an action stored")
		require.Empty(t, store.Queue())
		require.Equal(t, ackToken, store.AckToken())

		s, err = storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store1, err := NewStateStore(log, s)
		require.NoError(t, err)

		got := store1.Action()
		require.NotNil(t, got, "store should have an action stored")
		require.Empty(t, store1.Queue())
		require.Equal(t, want, got)
		require.Equal(t, ackToken, store.AckToken())
	})

	t.Run("errors when saving invalid action type", func(t *testing.T) {
		storePath := filepath.Join(t.TempDir(), "state.json")
		s, err := storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err := NewStateStore(log, s)
		require.NoError(t, err)

		store.state.ActionSerializer.Action = wrongAction{}
		store.dirty = true
		err = store.Save()
		require.ErrorContains(t, err, "incompatible type, expected")
	})

	t.Run("do not set action if it has the same ID", func(t *testing.T) {
		storePath := filepath.Join(t.TempDir(), "state.json")
		s, err := storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err := NewStateStore(log, s)
		require.NoError(t, err)

		want := &fleetapi.ActionUnenroll{
			ActionID:   "abc123",
			ActionType: "UNENROLL",
		}
		store.state.ActionSerializer.Action = want

		store.SetAction(&fleetapi.ActionUnenroll{
			ActionID:   "abc123",
			ActionType: "UNENROLL",
			IsDetected: true,
		})

		assert.Equal(t, want, store.state.ActionSerializer.Action)
	})

	t.Run("can save a queue with one upgrade action", func(t *testing.T) {
		ts := time.Now().UTC().Round(time.Second)
		queue := []fleetapi.ScheduledAction{&fleetapi.ActionUpgrade{
			ActionID:        "test",
			ActionType:      fleetapi.ActionTypeUpgrade,
			ActionStartTime: ts.Format(time.RFC3339),
			Data: fleetapi.ActionUpgradeData{
				Version:   "1.2.3",
				SourceURI: "https://example.com",
			}}}

		storePath := filepath.Join(t.TempDir(), "state.json")
		s, err := storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err := NewStateStore(log, s)
		require.NoError(t, err)

		require.Empty(t, store.Action())
		store.SetQueue(queue)
		err = store.Save()
		require.NoError(t, err)
		require.Empty(t, store.Action())
		require.Len(t, store.Queue(), 1)

		s, err = storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err = NewStateStore(log, s)
		require.NoError(t, err)

		assert.Nil(t, store.Action())
		assert.Len(t, store.Queue(), 1)
		assert.Equal(t, "test", store.Queue()[0].ID())

		start, err := store.Queue()[0].StartTime()
		assert.NoError(t, err)
		assert.Equal(t, ts, start)
	})

	t.Run("can save a queue with two actions", func(t *testing.T) {
		ts := time.Now().UTC().Round(time.Second)
		queue := []fleetapi.ScheduledAction{&fleetapi.ActionUpgrade{
			ActionID:        "test",
			ActionType:      fleetapi.ActionTypeUpgrade,
			ActionStartTime: ts.Format(time.RFC3339),
			Data: fleetapi.ActionUpgradeData{
				Version:   "1.2.3",
				SourceURI: "https://example.com",
				Retry:     1,
			}},
			// only the latest upgrade action is kept, however it's not the store
			// which handled that. Besides upgrade actions are the only
			// ScheduledAction right now, so it'll use 2 of them for this test.
			&fleetapi.ActionUpgrade{
				ActionID:        "test2",
				ActionType:      fleetapi.ActionTypeUpgrade,
				ActionStartTime: ts.Format(time.RFC3339),
				Data: fleetapi.ActionUpgradeData{
					Version:   "1.2.4",
					SourceURI: "https://example.com",
					Retry:     1,
				}}}

		storePath := filepath.Join(t.TempDir(), "state.json")
		s, err := storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err := NewStateStore(log, s)
		require.NoError(t, err)

		require.Empty(t, store.Action())
		store.SetQueue(queue)
		err = store.Save()
		require.NoError(t, err)
		require.Empty(t, store.Action())
		require.Len(t, store.Queue(), 2)

		// Load state store from disk
		s, err = storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err = NewStateStore(log, s)
		require.NoError(t, err, "could not load store from disk")

		got := store.Queue()
		for i, want := range queue {
			upgradeAction, ok := got[i].(*fleetapi.ActionUpgrade)
			assert.True(t, ok,
				"expected to be able to cast Action as ActionUpgrade")

			assert.Equal(t, want, upgradeAction, "saved action is different from expected")
		}
	})

	t.Run("when we ACK we save to disk", func(t *testing.T) {
		ActionPolicyChange := &fleetapi.ActionPolicyChange{
			ActionID: "abc123",
		}

		storePath := filepath.Join(t.TempDir(), "state.json")
		s, err := storage.NewDiskStore(storePath)
		require.NoError(t, err, "failed creating DiskStore")

		store, err := NewStateStore(log, s)
		require.NoError(t, err)
		store.SetAckToken(ackToken)

		acker := NewStateStoreActionAcker(&testAcker{}, store)
		require.Empty(t, store.Action())

		require.NoError(t, acker.Ack(context.Background(), ActionPolicyChange))
		require.NotNil(t, store.Action(), "store should have an action stored")
		require.Empty(t, store.Queue())
		require.Equal(t, ackToken, store.AckToken())
	})

	t.Run("state store is loaded from disk", func(t *testing.T) {
		t.Run("no store", func(t *testing.T) {
			storePath := filepath.Join(t.TempDir(), "state.json")

			s, err := storage.NewDiskStore(storePath)
			require.NoError(t, err, "failed creating DiskStore")

			stateStore, err := NewStateStore(log, s)
			require.NoError(t, err, "could not create disk store")

			assert.Empty(t, stateStore.Queue())
			assert.Empty(t, stateStore.Action())
			assert.Empty(t, stateStore.AckToken())
		})

		t.Run("empty store file", func(t *testing.T) {
			storePath := filepath.Join(t.TempDir(), "state.json")
			f, err := os.Create(storePath)
			require.NoError(t, err, "could not create store file")
			err = f.Close()
			require.NoError(t, err, "could not close store file")

			s, err := storage.NewDiskStore(storePath)
			require.NoError(t, err, "failed creating DiskStore")

			stateStore, err := NewStateStore(log, s)
			require.NoError(t, err, "could not create disk store")

			assert.Empty(t, stateStore.Queue())
			assert.Empty(t, stateStore.Action())
			assert.Empty(t, stateStore.AckToken())
		})

		t.Run("fails for invalid store content", func(t *testing.T) {
			t.Run("wrong store version", func(t *testing.T) {
				storePath := filepath.Join(t.TempDir(), "state.json")
				require.NoError(t,
					os.WriteFile(storePath, []byte(`{"version":"0"}`), 0600),
					"could not create store file")

				s, err := storage.NewDiskStore(storePath)
				require.NoError(t, err, "failed creating DiskStore")

				_, err = NewStateStore(log, s)
				require.Errorf(t, err,
					"state store creation should have failed with invalid store version")
			})

			t.Run("empty store version", func(t *testing.T) {
				storePath := filepath.Join(t.TempDir(), "state.json")
				require.NoError(t,
					os.WriteFile(storePath, []byte(`{"version":""}`), 0600),
					"could not create store file")

				s, err := storage.NewDiskStore(storePath)
				require.NoError(t, err, "failed creating DiskStore")

				_, err = NewStateStore(log, s)
				require.Errorf(t, err,
					"state store creation should have failed with invalid store version")
			})

			t.Run("garbage data/invalid JSON", func(t *testing.T) {
				storePath := filepath.Join(t.TempDir(), "state.json")
				require.NoError(t,
					os.WriteFile(storePath, []byte(`}`), 0600),
					"could not create store file")

				s, err := storage.NewDiskStore(storePath)
				require.NoError(t, err, "failed creating DiskStore")

				_, err = NewStateStore(log, s)
				require.Errorf(t, err,
					"state store creation should have failed")
			})
		})

		t.Run("ActionPolicyChange", func(t *testing.T) {
			storePath := filepath.Join(t.TempDir(), "state.json")
			want := &fleetapi.ActionPolicyChange{
				ActionID:   "abc123",
				ActionType: "POLICY_CHANGE",
				Data: fleetapi.ActionPolicyChangeData{
					Policy: map[string]interface{}{
						"hello":  "world",
						"phi":    1.618,
						"answer": 42.0,
					},
				},
			}

			s, err := storage.NewDiskStore(storePath)
			require.NoError(t, err, "failed creating DiskStore")

			stateStore, err := NewStateStore(log, s)
			require.NoError(t, err, "could not create disk store")

			stateStore.SetAckToken(ackToken)
			stateStore.SetAction(want)
			err = stateStore.Save()
			require.NoError(t, err, "failed saving state store")

			// to load from disk a new store needs to be created
			s, err = storage.NewDiskStore(storePath)
			require.NoError(t, err, "failed creating DiskStore")

			stateStore, err = NewStateStore(log, s)
			require.NoError(t, err, "could not create disk store")

			action := stateStore.Action()
			require.NotNil(t, action, "should have loaded an action")
			got, ok := action.(*fleetapi.ActionPolicyChange)
			require.True(t, ok, "could not cast action to fleetapi.ActionPolicyChange")
			assert.Equal(t, want, got)

			emptyFields := hasEmptyFields(got)
			if len(emptyFields) > 0 {
				t.Errorf("the following fields of %T are serialized and are empty: %s."+
					" All serialised fields must have a value. Perhaps the action was"+
					" updated but this test was not. Ensure the test covers all"+
					"JSON serialized fields for this action.",
					got, emptyFields)
			}
		})

		t.Run("ActionUnenroll", func(t *testing.T) {
			storePath := filepath.Join(t.TempDir(), "state.json")
			want := &fleetapi.ActionUnenroll{
				ActionID:   "abc123",
				ActionType: fleetapi.ActionTypeUnenroll,
				IsDetected: true,
				Signed: &fleetapi.Signed{
					Data:      "some data",
					Signature: "a signature",
				},
			}

			s, err := storage.NewDiskStore(storePath)
			require.NoError(t, err, "failed creating DiskStore")

			stateStore, err := NewStateStore(log, s)
			require.NoError(t, err, "could not create disk store")

			stateStore.SetAckToken(ackToken)
			stateStore.SetAction(want)
			err = stateStore.Save()
			require.NoError(t, err, "failed saving state store")

			// to load from disk a new store needs to be created
			s, err = storage.NewDiskStore(storePath)
			require.NoError(t, err, "failed creating DiskStore")

			stateStore, err = NewStateStore(log, s)
			require.NoError(t, err, "could not create disk store")

			action := stateStore.Action()
			require.NotNil(t, action, "should have loaded an action")
			got, ok := action.(*fleetapi.ActionUnenroll)
			require.True(t, ok, "could not cast action to fleetapi.ActionUnenroll")
			assert.Equal(t, want, got)

			emptyFields := hasEmptyFields(got)
			if len(emptyFields) > 0 {
				t.Errorf("the following fields of %T are serialized and are empty: %s."+
					" All serialised fields must have a value. Perhaps the action was"+
					" updated but this test was not. Ensure the test covers all"+
					"JSON serialized fields for this action.",
					got, emptyFields)
			}
		})

		t.Run("action queue", func(t *testing.T) {
			storePath := filepath.Join(t.TempDir(), "state.json")
			now := time.Now().UTC().Round(time.Second)
			want := &fleetapi.ActionUpgrade{
				ActionID:         "test",
				ActionType:       fleetapi.ActionTypeUpgrade,
				ActionStartTime:  now.Format(time.RFC3339),
				ActionExpiration: now.Add(time.Hour).Format(time.RFC3339),
				Data: fleetapi.ActionUpgradeData{
					Version:   "1.2.3",
					SourceURI: "https://example.com",
					Retry:     1,
				},
				Signed: &fleetapi.Signed{
					Data:      "some data",
					Signature: "a signature",
				},
			}

			s, err := storage.NewDiskStore(storePath)
			require.NoError(t, err, "failed creating DiskStore")

			stateStore, err := NewStateStore(log, s)
			require.NoError(t, err, "could not create disk store")

			stateStore.SetAckToken(ackToken)
			stateStore.SetQueue([]fleetapi.ScheduledAction{want})
			err = stateStore.Save()
			require.NoError(t, err, "failed saving state store")

			// to load from disk a new store needs to be created
			s, err = storage.NewDiskStore(storePath)
			require.NoError(t, err, "failed creating DiskStore")

			stateStore, err = NewStateStore(log, s)
			require.NoError(t, err, "could not create disk store")

			queue := stateStore.Queue()
			require.Len(t, queue, 1, "action queue should have only 1 action")
			got := queue[0]
			assert.Equal(t, want, got,
				"deserialized action is different from what was saved to disk")
			_, ok := got.(*fleetapi.ActionUpgrade)
			require.True(t, ok, "could not cast action in the queue to upgradeAction")

			emptyFields := hasEmptyFields(got)
			if len(emptyFields) > 0 {
				t.Errorf("the following fields of %T are serialized and are empty: %s."+
					" All serialised fields must have a value. Perhaps the action was"+
					" updated but this test was not. Ensure the test covers all"+
					"JSON serialized fields for this action.",
					got, emptyFields)
			}
		})
	})
}

type testAcker struct {
	acked     []string
	ackedLock sync.Mutex
}

func (t *testAcker) Ack(_ context.Context, action fleetapi.Action) error {
	t.ackedLock.Lock()
	defer t.ackedLock.Unlock()

	if t.acked == nil {
		t.acked = make([]string, 0)
	}

	t.acked = append(t.acked, action.ID())
	return nil
}

func (t *testAcker) Commit(_ context.Context) error {
	return nil
}

func (t *testAcker) Clear() {
	t.ackedLock.Lock()
	defer t.ackedLock.Unlock()

	t.acked = make([]string, 0)
}

func (t *testAcker) Items() []string {
	t.ackedLock.Lock()
	defer t.ackedLock.Unlock()
	return t.acked
}

// hasEmptyFields will check if action has any empty fields. It returns a string
// slice with any empty field, the field value is the zero value for its type.
// If the json tag of the field is "-", the field is ignored.
// If no field is empty, it returns nil.
func hasEmptyFields(action fleetapi.Action) []string {
	var actionValue reflect.Value
	actionValue = reflect.ValueOf(action)
	// dereference if it's a pointer
	if actionValue.Kind() == reflect.Pointer {
		actionValue = actionValue.Elem()
	}

	var failures []string
	for i := 0; i < actionValue.NumField(); i++ {
		fieldValue := actionValue.Field(i)
		actionType := actionValue.Type()
		structField := actionType.Field(i)

		fieldName := structField.Name
		tag := structField.Tag.Get("json")

		// If the field isn't serialised, ignore it.
		if tag == "-" {
			continue
		}

		got := fieldValue.Interface()
		zeroValue := reflect.Zero(fieldValue.Type()).Interface()

		if reflect.DeepEqual(got, zeroValue) {
			failures = append(failures, fieldName)
		}
	}

	return failures
}
