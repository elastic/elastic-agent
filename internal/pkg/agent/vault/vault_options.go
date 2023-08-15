// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package vault

import "time"

const defaultRetryDelay = 10 * time.Millisecond

type Options struct {
	readonly   bool
	retryDelay time.Duration
}

type OptionFunc func(o *Options)

func WithReadonly(readonly bool) OptionFunc {
	return func(o *Options) {
		o.readonly = readonly
	}
}

func WithRetryDelay(retryDelay time.Duration) OptionFunc {
	return func(o *Options) {
		if retryDelay > 0 {
			o.retryDelay = retryDelay
		}
	}
}

func applyOptions(opts ...OptionFunc) Options {
	options := Options{
		retryDelay: defaultRetryDelay,
	}

	for _, opt := range opts {
		opt(&options)
	}

	return options
}
