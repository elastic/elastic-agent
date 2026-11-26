// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"context"
)

const unsupportedReason = "not implemented for this platform"

type unsupportedBackend struct{}

// NewUnsupportedBackend returns a Backend that reports every call as unsupported.
func NewUnsupportedBackend() Backend {
	return unsupportedBackend{}
}

func (unsupportedBackend) LogicalCPUs(context.Context) (int, error) {
	return 0, &UnsupportedError{Reason: unsupportedReason}
}

func (unsupportedBackend) Inspect(context.Context) (Inspection, error) {
	return Inspection{}, &UnsupportedError{Reason: unsupportedReason}
}

func (unsupportedBackend) Apply(context.Context, float64) error {
	return &UnsupportedError{Reason: unsupportedReason}
}

func (unsupportedBackend) Remove(context.Context) error {
	return &UnsupportedError{Reason: unsupportedReason}
}
