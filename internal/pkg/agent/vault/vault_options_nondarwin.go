// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows

package vault

import "time"

const defaultRetryDelay = 10 * time.Millisecond

func applyOptions(opts ...OptionFunc) Options {
	options := Options{
		retryDelay: defaultRetryDelay,
	}

	for _, opt := range opts {
		opt(&options)
	}

	return options
}
