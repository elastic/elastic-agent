// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package vault

type Options struct {
	readonly bool
}

type OptionFunc func(o *Options)

func WithReadonly(readonly bool) OptionFunc {
	return func(o *Options) {
		o.readonly = readonly
	}
}

//nolint:unused // not used on darwin
func applyOptions(opts ...OptionFunc) Options {
	var options Options

	for _, opt := range opts {
		opt(&options)
	}

	return options
}
