// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package filelock

import "context"

type noopLocker struct{}

func NewNoopLocker() *noopLocker {
	return &noopLocker{}
}

func (*noopLocker) Lock() error                         { return nil }
func (*noopLocker) LockContext(_ context.Context) error { return nil }

func (*noopLocker) Unlock() error { return nil }

func (*noopLocker) Locked() bool { return false }
