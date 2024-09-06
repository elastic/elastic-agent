// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package vault

import (
	"context"
	"runtime"
	"time"
)

const (
	// defaultFlockRetryDelay default file lock retry delay
	defaultFlockRetryDelay = 10 * time.Millisecond

	// lock file name
	lockFile = `.lock`
)

type Vault interface {
	Exists(ctx context.Context, key string) (bool, error)
	Get(ctx context.Context, key string) (dec []byte, err error)
	Set(ctx context.Context, key string, data []byte) (err error)
	Remove(ctx context.Context, key string) (err error)
	Close() error
}

func New(ctx context.Context, opts ...OptionFunc) (Vault, error) {
	options, err := ApplyOptions(opts...)
	if err != nil {
		return nil, err
	}

	if runtime.GOOS == "darwin" && !options.unprivileged {
		return NewDarwinKeyChainVault(ctx, options)
	}

	return NewFileVault(ctx, options)
}
