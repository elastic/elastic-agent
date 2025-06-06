// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package filelock

import (
	"fmt"
	"os"
	"path/filepath"
)

// ErrAppAlreadyRunning error returned when another elastic-agent is already holding the lock.
var ErrAppAlreadyRunning = fmt.Errorf("another elastic-agent is already running")

// AppLocker locks the agent.lock file inside the provided directory.
type AppLocker struct {
	*FileLocker
}

// NewAppLocker creates an AppLocker that locks the agent.lock file inside the provided directory.
func NewAppLocker(dir, lockFileName string) *AppLocker {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		_ = os.Mkdir(dir, 0755)
	}

	lockFilePath := filepath.Join(dir, lockFileName)
	lock, err := NewFileLocker(lockFilePath, WithCustomNotLockedError(ErrAppAlreadyRunning))
	if err != nil {
		// should never happen, if it does something is seriously wrong. Better to abort here and let a human take over.
		panic(fmt.Errorf("creating new file locker %s: %s", lockFilePath, err))
	}

	return &AppLocker{FileLocker: lock}
}

// TryLock tries to grab the lock file and returns error if it cannot.
func (a *AppLocker) TryLock() error {
	return a.Lock()
}
