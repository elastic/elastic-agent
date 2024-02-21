// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package store

import (
	"errors"
	"fmt"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store/internal/migrations"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var ErrInvalidYAML = errors.New("could not parse YAML")

func migrateActionStoreToStateStore(
	log *logger.Logger,
	actionStorePath string,
	stateDiskStore storage.Storage) (err error) {

	log = log.Named("state_migration")
	actionDiskStore := storage.NewDiskStore(actionStorePath)

	stateStoreExits, err := stateDiskStore.Exists()
	if err != nil {
		log.Errorf("failed to check if state store exists: %v", err)
		return err
	}

	// do not migrate if the state store already exists
	if stateStoreExits {
		log.Debugf("state store already exists")
		return nil
	}

	actionStoreExits, err := actionDiskStore.Exists()
	if err != nil {
		log.Errorf("failed to check if action store %s exists: %v", actionStorePath, err)
		return err
	}

	// delete the actions store file upon successful migration
	defer func() {
		if err == nil && actionStoreExits {
			err = actionDiskStore.Delete()
			if err != nil {
				log.Errorf("failed to delete action store %s exists: %v", actionStorePath, err)
			}
		}
	}()

	// nothing to migrate if the action store doesn't exists
	if !actionStoreExits {
		log.Debugf("action store %s doesn't exists, nothing to migrate", actionStorePath)
		return nil
	}

	action, err := migrations.LoadActionStore(actionDiskStore)
	if err != nil {
		log.Errorf("failed to create action store %s: %v", actionStorePath, err)
		return err
	}

	// no actions stored nothing to migrate
	if action == nil {
		log.Debugf("no action stored in the action store %s, nothing to migrate", actionStorePath)
		return nil
	}

	stateStore, err := NewStateStore(log, stateDiskStore)
	if err != nil {
		return err
	}

	// set actions from the action store to the state store
	stateStore.SetAction(&fleetapi.ActionPolicyChange{
		ActionID:   action.ActionID,
		ActionType: action.Type,
		Data:       fleetapi.ActionPolicyChangeData{Policy: action.Policy},
	})

	err = stateStore.Save()
	if err != nil {
		log.Debugf("failed to save agent state store, err: %v", err)
	}
	return err
}

// migrateYAMLStateStoreToStateStoreV1 migrates the YAML store to the new JSON
// state store. If the contents of store is already a JSON, it returns the
// parsed JSON.
func migrateYAMLStateStoreToStateStoreV1(store storage.Storage) error {
	exists, err := store.Exists()
	if err != nil {
		return fmt.Errorf("migration YMAL to Store v1 failed: "+
			"could not load store from disk: %w", err)
	}

	// nothing to migrate, return empty store.
	if !exists {
		return nil
	}

	// JSON is a subset of YAML, so first check if it's already a JSON store.
	reader, err := store.Load()
	if err != nil {
		return fmt.Errorf("could not read store content: %w", err)
	}

	st, err := readState(reader)
	if err == nil {
		// it's a valid JSON, therefore nothing to migrate
		return nil
	}

	err = reader.Close()
	if err != nil {
		return fmt.Errorf("could not close store reader: %w", err)
	}

	// Try to read the store as YAML
	yamlStore, err := migrations.LoadYAMLStateStore(store)
	if err != nil {
		// it isn't a YAML store
		return errors.Join(ErrInvalidYAML, err)
	}

	// Store was empty, nothing to migrate
	if yamlStore == nil {
		return nil
	}

	var action fleetapi.Action
	switch yamlStore.Action.Type {
	case fleetapi.ActionTypePolicyChange:
		action = &fleetapi.ActionPolicyChange{
			ActionID:   yamlStore.Action.ActionID,
			ActionType: yamlStore.Action.Type,
			Data: fleetapi.ActionPolicyChangeData{
				Policy: yamlStore.Action.Policy},
		}
	case fleetapi.ActionTypeUnenroll:
		action = &fleetapi.ActionUnenroll{
			ActionID:   yamlStore.Action.ActionID,
			ActionType: yamlStore.Action.Type,
			IsDetected: yamlStore.Action.IsDetected,
		}
	}

	var queue actionQueue
	for _, a := range yamlStore.ActionQueue {
		queue = append(queue,
			&fleetapi.ActionUpgrade{
				ActionID:         a.ActionID,
				ActionType:       a.Type,
				ActionStartTime:  a.StartTime.Format(time.RFC3339),
				ActionExpiration: a.ExpirationTime.Format(time.RFC3339),
				Data: fleetapi.ActionUpgradeData{
					Version:   a.Version,
					SourceURI: a.SourceURI,
					Retry:     a.RetryAttempt,
				},
			})
	}

	st = state{
		Version:          "1",
		ActionSerializer: actionSerializer{Action: action},
		AckToken:         yamlStore.AckToken,
		Queue:            queue,
	}

	jsonReader, err := jsonToReader(&st)
	if err != nil {
		return fmt.Errorf("store state migrated from YAML failed: %w", err)
	}

	err = store.Save(jsonReader)
	if err != nil {
		return fmt.Errorf("failed to save store state migrated from YAML: %w", err)
	}

	return nil
}
