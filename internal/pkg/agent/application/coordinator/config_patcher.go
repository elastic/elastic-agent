// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package coordinator

import (
	"context"
)

type ConfigPatch func(change ConfigChange) ConfigChange

// ConfigPatchManager is a decorator to restore some agent settings from the elastic agent configuration file
type ConfigPatchManager struct {
	inner   ConfigManager
	outCh   chan ConfigChange
	patchFn ConfigPatch
}

func (c ConfigPatchManager) Run(ctx context.Context) error {
	go c.patch(c.inner.Watch(), c.outCh)
	return c.inner.Run(ctx)
}

func (c ConfigPatchManager) Errors() <-chan error {
	return c.inner.Errors()
}

func (c ConfigPatchManager) ActionErrors() <-chan error {
	return c.inner.ActionErrors()
}

func (c ConfigPatchManager) Watch() <-chan ConfigChange {
	return c.outCh
}

func (c ConfigPatchManager) patch(src <-chan ConfigChange, dst chan ConfigChange) {
	for ccc := range src {
		dst <- c.patchFn(ccc)
	}
}

func NewConfigPatchManager(inner ConfigManager, pf ConfigPatch) *ConfigPatchManager {
	return &ConfigPatchManager{
		inner:   inner,
		outCh:   make(chan ConfigChange),
		patchFn: pf,
	}
}
