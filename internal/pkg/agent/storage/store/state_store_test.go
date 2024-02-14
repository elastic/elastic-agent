// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package store

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestMyTest(t *testing.T) {
	log, _ := logger.NewTesting("TestMyTest")
	ackToken := "ackToken"
	t.Run("ActionPolicyChange", func(t *testing.T) {
		storePath := filepath.Join(t.TempDir(), "state.yaml")
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

		s := storage.NewDiskStore(storePath)
		stateStore, err := NewStateStore(log, s)
		require.NoError(t, err, "could not create disk store")

		stateStore.SetAckToken(ackToken)
		stateStore.SetAction(want)
		err = stateStore.Save()
		require.NoError(t, err, "failed saving state store")

		// to load from disk a new store needs to be created
		s = storage.NewDiskStore(storePath)
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
}
func TestStateStore(t *testing.T) {
	t.Run("ack token", func(t *testing.T) {
		runTestStateStore(t, "czlV93YBwdkt5lYhBY7S")
	})

	t.Run("no ack token", func(t *testing.T) {
		runTestStateStore(t, "")
	})
}

func runTestStateStore(t *testing.T, ackToken string) {
	log, _ := logger.New("state_store", false)

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	t.Run("action returns empty when no action is saved on disk", func(t *testing.T) {
		storePath := filepath.Join(t.TempDir(), "state.yml")
		s := storage.NewDiskStore(storePath)
		store, err := NewStateStore(log, s)
		require.NoError(t, err)
		require.Empty(t, store.Action())
		require.Empty(t, store.Queue())
	})

	t.Run("will discard silently unknown action", func(t *testing.T) {
		actionPolicyChange := &fleetapi.ActionUnknown{
			ActionID: "abc123",
		}

		storePath := filepath.Join(t.TempDir(), "state.yml")
		s := storage.NewDiskStore(storePath)
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

	t.Run("can save to disk known action type", func(t *testing.T) {
		ActionPolicyChange := &fleetapi.ActionPolicyChange{
			ActionID:   "abc123",
			ActionType: "POLICY_CHANGE",
			Data: fleetapi.ActionPolicyChangeData{
				Policy: map[string]interface{}{
					"hello": "world",
				}},
		}

		storePath := filepath.Join(t.TempDir(), "state.yml")
		s := storage.NewDiskStore(storePath)
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

		s = storage.NewDiskStore(storePath)
		store1, err := NewStateStore(log, s)
		require.NoError(t, err)

		action := store1.Action()
		require.NotNil(t, action, "store should have an action stored")
		require.Empty(t, store1.Queue())

		require.Equal(t, ActionPolicyChange, action)
		require.Equal(t, ackToken, store.AckToken())
	})

	t.Run("can save a queue with one upgrade action", func(t *testing.T) {
		ts := time.Now().UTC().Round(time.Second)
		queue := fleetapi.Actions{&fleetapi.ActionUpgrade{
			ActionID:        "test",
			ActionType:      fleetapi.ActionTypeUpgrade,
			ActionStartTime: ts.Format(time.RFC3339),
			Data: fleetapi.ActionUpgradeData{
				Version:   "1.2.3",
				SourceURI: "https://example.com",
			}}}

		storePath := filepath.Join(t.TempDir(), "state.yml")
		s := storage.NewDiskStore(storePath)
		store, err := NewStateStore(log, s)
		require.NoError(t, err)

		require.Empty(t, store.Action())
		store.SetQueue(queue)
		err = store.Save()
		require.NoError(t, err)
		require.Empty(t, store.Action())
		require.Len(t, store.Queue(), 1)

		s = storage.NewDiskStore(storePath)
		store1, err := NewStateStore(log, s)
		require.NoError(t, err)
		require.Empty(t, store1.Action())
		require.Len(t, store1.Queue(), 1)
		require.Equal(t, "test", store1.Queue()[0].ID())
		scheduledAction, ok := store1.Queue()[0].(fleetapi.ScheduledAction)
		require.True(t, ok, "expected to be able to cast Action as ScheduledAction")
		start, err := scheduledAction.StartTime()
		require.NoError(t, err)
		require.Equal(t, ts, start)
	})

	t.Run("can save a queue with two actions", func(t *testing.T) {
		ts := time.Now().UTC().Round(time.Second)
		queue := fleetapi.Actions{&fleetapi.ActionUpgrade{
			ActionID:        "test",
			ActionType:      fleetapi.ActionTypeUpgrade,
			ActionStartTime: ts.Format(time.RFC3339),
			Data: fleetapi.ActionUpgradeData{
				Version:   "1.2.3",
				SourceURI: "https://example.com",
				Retry:     1,
			}}, &fleetapi.ActionPolicyChange{
			ActionID:   "abc123",
			ActionType: "POLICY_CHANGE",
			Data: fleetapi.ActionPolicyChangeData{
				Policy: map[string]interface{}{
					"hello": "world",
				}},
		}}

		storePath := filepath.Join(t.TempDir(), "state.yml")
		s := storage.NewDiskStore(storePath)
		store, err := NewStateStore(log, s)
		require.NoError(t, err)

		require.Empty(t, store.Action())
		store.SetQueue(queue)
		err = store.Save()
		require.NoError(t, err)
		require.Empty(t, store.Action())
		require.Len(t, store.Queue(), 2)

		s = storage.NewDiskStore(storePath)
		store1, err := NewStateStore(log, s)
		require.NoError(t, err)
		require.Empty(t, store1.Action())
		require.Len(t, store1.Queue(), 2)

		require.Equal(t, "test", store1.Queue()[0].ID())
		scheduledAction, ok := store1.Queue()[0].(fleetapi.ScheduledAction)
		require.True(t, ok, "expected to be able to cast Action as ScheduledAction")
		start, err := scheduledAction.StartTime()
		require.NoError(t, err)
		require.Equal(t, ts, start)
		retryableAction, ok := store1.Queue()[0].(fleetapi.RetryableAction)
		require.True(t, ok, "expected to be able to cast Action as RetryableAction")
		require.Equal(t, 1, retryableAction.RetryAttempt())

		require.Equal(t, "abc123", store1.Queue()[1].ID())
		_, ok = store1.Queue()[1].(fleetapi.ScheduledAction)
		require.False(t, ok, "expected cast to ScheduledAction to fail")
	})

	t.Run("can save to disk unenroll action type", func(t *testing.T) {
		want := &fleetapi.ActionUnenroll{
			ActionID:   "abc123",
			ActionType: "UNENROLL",
		}

		storePath := filepath.Join(t.TempDir(), "state.yml")
		s := storage.NewDiskStore(storePath)
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

		s = storage.NewDiskStore(storePath)
		store1, err := NewStateStore(log, s)
		require.NoError(t, err)

		got := store1.Action()
		require.NotNil(t, got, "store should have an action stored")
		require.Empty(t, store1.Queue())
		require.Equal(t, want, got)
		require.Equal(t, ackToken, store.AckToken())
	})

	t.Run("when we ACK we save to disk", func(t *testing.T) {
		ActionPolicyChange := &fleetapi.ActionPolicyChange{
			ActionID: "abc123",
		}

		storePath := filepath.Join(t.TempDir(), "state.yml")
		s := storage.NewDiskStore(storePath)
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

	t.Run("migrate actions file does not exists", func(t *testing.T) {
		if runtime.GOOS == "darwin" {
			// the original test never actually run, so with this at least
			// there is coverage for linux and windows.
			t.Skipf("needs https://github.com/elastic/elastic-agent/issues/3866" +
				"to be merged so this test can work on darwin")
		}

		tempDir := t.TempDir()
		oldActionStorePath := filepath.Join(tempDir, "action_store.yml")
		newStateStorePath := filepath.Join(tempDir, "state_store.yml")

		newStateStore := storage.NewEncryptedDiskStore(ctx, newStateStorePath)
		err := migrateActionStoreToStateStore(log, oldActionStorePath, newStateStore)
		require.NoError(t, err, "migration action store -> state store failed")

		// to load from disk a new store needs to be created, it loads the file
		// to memory during the store creation.
		stateStore, err := NewStateStore(log, storage.NewDiskStore(newStateStorePath))
		require.NoError(t, err)
		stateStore.SetAckToken(ackToken)
		require.Empty(t, stateStore.Action())
		require.Equal(t, ackToken, stateStore.AckToken())
		require.Empty(t, stateStore.Queue())
	})

	t.Run("migrate", func(t *testing.T) {
		// TODO: DO NOT MERGE TO MAIN WITHOUT REMOVING THIS SKIP
		t.Skip("this test is broken because the migration haven't been" +
			" implemented yet. It'll implemented on another PR as part of" +
			"https://github.com/elastic/elastic-agent/issues/3912")

		if runtime.GOOS == "darwin" {
			// the original migrate never actually run, so with this at least
			// there is coverage for linux and windows.
			t.Skipf("needs https://github.com/elastic/elastic-agent/issues/3866" +
				"to be merged so this test can work on darwin")
		}

		want := &fleetapi.ActionPolicyChange{
			ActionID:   "abc123",
			ActionType: "POLICY_CHANGE",
			Data: fleetapi.ActionPolicyChangeData{
				Policy: map[string]interface{}{
					"hello":  "world",
					"phi":    1.618,
					"answer": 42,
				},
			},
		}

		tempDir := t.TempDir()
		vaultPath := filepath.Join(tempDir, "vault")
		err := os.MkdirAll(vaultPath, 0o750)
		require.NoError(t, err,
			"could not create directory for the agent's vault")
		_, err = vault.New(ctx, vaultPath)
		require.NoError(t, err, "could not create agent's vault")
		err = secret.CreateAgentSecret(
			context.Background(), secret.WithVaultPath(vaultPath))
		require.NoError(t, err, "could not create agent secret")

		// Copy the golden file as the migration deletes the old store.
		goldenActionStoreFile, err := os.Open(
			filepath.Join("testdata", "7.17.18-action_store.yml"))
		require.NoError(t, err, "could not open action store golden file")
		defer goldenActionStoreFile.Close()

		oldActionStorePath := filepath.Join(tempDir, "action_store.yml")
		storeFile, err := os.Create(oldActionStorePath)
		require.NoError(t, err, "could not create action store file")

		_, err = io.Copy(storeFile, goldenActionStoreFile)
		require.NoError(t, err, "could not copy action store golden file")
		err = storeFile.Close()
		// It needs to be closed now otherwise on windows the store will fail to
		// open the file.
		require.NoError(t, err, "could not close store file")

		newStateStorePath := filepath.Join(tempDir, "state_store.yaml")
		newStateStore := storage.NewEncryptedDiskStore(ctx, newStateStorePath,
			storage.WithVaultPath(vaultPath))
		err = migrateActionStoreToStateStore(log, oldActionStorePath, newStateStore)
		require.NoError(t, err, "migration action store -> state store failed")

		// to load from disk a new store needs to be created, it loads the file
		// to memory during the store creation.
		newStateStore = storage.NewEncryptedDiskStore(ctx, newStateStorePath,
			storage.WithVaultPath(vaultPath))
		stateStore, err := NewStateStore(log, newStateStore)
		require.NoError(t, err, "could not create state store")

		got := stateStore.Action()
		require.NotNil(t, got, "should have loaded an action")

		assert.Equalf(t, want, got,
			"loaded action differs from action on the old action store")
		assert.Empty(t, stateStore.Queue(),
			"queue should be empty, old action store did not have a queue")
	})

	t.Run("state store is correctly loaded from disk", func(t *testing.T) {
		t.Run("ActionPolicyChange", func(t *testing.T) {
			storePath := filepath.Join(t.TempDir(), "state.yaml")
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

			s := storage.NewDiskStore(storePath)
			stateStore, err := NewStateStore(log, s)
			require.NoError(t, err, "could not create disk store")

			stateStore.SetAckToken(ackToken)
			stateStore.SetAction(want)
			err = stateStore.Save()
			require.NoError(t, err, "failed saving state store")

			// to load from disk a new store needs to be created
			s = storage.NewDiskStore(storePath)
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
			storePath := filepath.Join(t.TempDir(), "state.yaml")
			want := &fleetapi.ActionUnenroll{
				ActionID:   "abc123",
				ActionType: fleetapi.ActionTypeUnenroll,
				IsDetected: true,
				Signed: &fleetapi.Signed{
					Data:      "some data",
					Signature: "a signature",
				},
			}

			s := storage.NewDiskStore(storePath)
			stateStore, err := NewStateStore(log, s)
			require.NoError(t, err, "could not create disk store")

			stateStore.SetAckToken(ackToken)
			stateStore.SetAction(want)
			err = stateStore.Save()
			require.NoError(t, err, "failed saving state store")

			// to load from disk a new store needs to be created
			s = storage.NewDiskStore(storePath)
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
			storePath := filepath.Join(t.TempDir(), "state.yaml")
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

			t.Logf("state store: %q", storePath)
			s := storage.NewDiskStore(storePath)
			stateStore, err := NewStateStore(log, s)
			require.NoError(t, err, "could not create disk store")

			stateStore.SetAckToken(ackToken)
			stateStore.SetQueue(fleetapi.Actions{want})
			err = stateStore.Save()
			require.NoError(t, err, "failed saving state store")

			// to load from disk a new store needs to be created
			s = storage.NewDiskStore(storePath)
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
