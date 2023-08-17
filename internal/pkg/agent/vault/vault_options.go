// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package vault

type OptionFunc func(o *Options)

// WithReadonly opens storage for read-only access only, noop for Darwin
func WithReadonly(readonly bool) OptionFunc {
	return func(o *Options) {
		o.readonly = readonly
	}
}
