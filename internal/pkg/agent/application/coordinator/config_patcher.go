package coordinator

import (
	"context"
)

type ConfigPatch func(change ConfigChange) ConfigChange

// ConfigPatchManager is a decorator to restore some agent settings from the elastic agent configuration file
type ConfigPatchManager struct {
	inner  ConfigManager
	outch  chan ConfigChange
	patchf ConfigPatch
}

func (c ConfigPatchManager) Run(ctx context.Context) error {
	go c.patch(c.inner.Watch(), c.outch)
	return c.inner.Run(ctx)
}

func (c ConfigPatchManager) Errors() <-chan error {
	return c.inner.Errors()
}

func (c ConfigPatchManager) ActionErrors() <-chan error {
	return c.inner.ActionErrors()
}

func (c ConfigPatchManager) Watch() <-chan ConfigChange {
	return c.outch
}

func (c ConfigPatchManager) patch(src <-chan ConfigChange, dst chan ConfigChange) {
	for ccc := range src {
		dst <- c.patchf(ccc)
	}
}

func NewConfigPatchManager(inner ConfigManager, pf ConfigPatch) *ConfigPatchManager {
	return &ConfigPatchManager{
		inner:  inner,
		outch:  make(chan ConfigChange),
		patchf: pf,
	}
}
