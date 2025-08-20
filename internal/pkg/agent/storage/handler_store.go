// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package storage

import (
	"io"

	"github.com/elastic/elastic-agent-libs/file"
)

type handlerFunc func(io.Reader, ...file.RotateOpt) error

// HandlerStore take a function handler and wrap it into the store interface.
type HandlerStore struct {
	fn handlerFunc
}

// NewHandlerStore takes a function and wrap it into an handlerStore.
func NewHandlerStore(fn handlerFunc) *HandlerStore {
	return &HandlerStore{fn: fn}
}

// Save calls the handler.
func (h *HandlerStore) Save(in io.Reader, rotateOpts ...file.RotateOpt) error {
	return h.fn(in, rotateOpts...)
}
