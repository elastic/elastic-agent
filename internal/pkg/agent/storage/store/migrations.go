// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package store

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store/internal/migrations"
	"github.com/elastic/elastic-agent/internal/pkg/conv"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var ErrInvalidYAML = errors.New("could not parse YAML")

func migrateActionStoreToStateStore(
	log *logger.Logger,
	actionStorePath string,
	stateDiskStore storage.Storage) (err error) {

	log = log.Named("state_migration")
	actionDiskStore, err := storage.NewDiskStore(actionStorePath)
	if err != nil {
		return fmt.Errorf(
			"could not create disk store when migratins action store: %w", err)
	}

	stateStoreExists, err := stateDiskStore.Exists()
	if err != nil {
		return fmt.Errorf("failed to check if state store exists: %w", err)
	}

	// do not migrate if the state store already exists
	if stateStoreExists {
		log.Debugf("not attempting to migrate from action store: state store already exists")
		return nil
	}

	actionStoreExists, err := actionDiskStore.Exists()
	if err != nil {
		return fmt.Errorf("failed to check if action store %s exists: %w", actionStorePath, err)
	}

	// nothing to migrate if the action store doesn't exist
	if !actionStoreExists {
		log.Debugf("action store %s doesn't exists, nothing to migrate", actionStorePath)
		return nil
	}
	// delete the actions store file upon successful migration
	defer func() {
		if err == nil {
			err = actionDiskStore.Delete()
			if err != nil {
				log.Errorf("failed to delete action store %s after migration: %v", actionStorePath, err)
			}
		}
	}()

	action, err := migrations.LoadActionStore(actionDiskStore)
	if err != nil {
		return fmt.Errorf("failed to load action store for migration %s: %w",
			actionStorePath, err)
	}

	// no actions stored nothing to migrate
	if action == nil {
		log.Debugf("no action stored in the action store %s, nothing to migrate", actionStorePath)
		return nil
	}

	supportedActions := []string{
		fleetapi.ActionTypePolicyChange,
		// Unenroll action is supported for completeness as an unenrolled agent
		// would not be upgraded.
		fleetapi.ActionTypeUnenroll,
	}
	if !slices.Contains(supportedActions, action.Type) {
		log.Warnf("unexpected action type when migrating from action store. "+
			"Found %s, but only %v are suported. Ignoring action and proceeding.",
			action.Type, supportedActions)
		// If it isn't ignored, the agent will be stuck here and require manual
		// intervention to fix the store.
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
		Data: fleetapi.ActionPolicyChangeData{
			Policy: conv.YAMLMapToJSONMap(action.Policy),
		},
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
func migrateYAMLStateStoreToStateStoreV1(log *logger.Logger, store storage.Storage) error {
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
	// close it as soon as possible and before the next store save
	_ = reader.Close()
	if err == nil {
		// it's a valid JSON, therefore nothing to migrate
		return nil
	}

	// Try to read the store as YAML
	yamlStore, err := migrations.LoadYAMLStateStore(store)
	if err != nil {
		// it isn't a YAML store
		return errors.Join(ErrInvalidYAML, err)
	}
	// nil here would mean an empty store. However and empty file is a valid
	// JSON store as well. Thus, it should never reach this point. Nevertheless,
	// better to ensue it does not proceed if the store is nil.
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
				Policy: conv.YAMLMapToJSONMap(yamlStore.Action.Policy)},
		}
		// Unenroll action is supported for completeness as an unenrolled agent
		// would not be upgraded.
	case fleetapi.ActionTypeUnenroll:
		action = &fleetapi.ActionUnenroll{
			ActionID:   yamlStore.Action.ActionID,
			ActionType: yamlStore.Action.Type,
			IsDetected: yamlStore.Action.IsDetected,
		}
	default:
		log.Warnf("loaded a unsupported %s action from the deprecated YAML state store, ignoring it",
			yamlStore.Action.Type)
	}

	var queue actionQueue
	for _, a := range yamlStore.ActionQueue {
		if a.Type != fleetapi.ActionTypeUpgrade {
			log.Warnf(
				"loaded a unsupported %s action from the deprecated YAML state store action queue, it will be dropped",
				yamlStore.Action.Type)
			continue
		}

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
