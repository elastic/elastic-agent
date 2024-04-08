// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package perms

import (
	"os"

	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	defaultMask = 0770
)

type opts struct {
	mask      os.FileMode
	ownership utils.FileOwner
}

type OptFunc func(o *opts)

// WithMask adjusts the default mask used.
func WithMask(mask os.FileMode) OptFunc {
	return func(o *opts) {
		o.mask = mask
	}
}

// WithOwnership sets the ownership for the permissions
func WithOwnership(ownership utils.FileOwner) OptFunc {
	return func(o *opts) {
		o.ownership = ownership
	}
}

func newOpts(optFuncs ...OptFunc) *opts {
	o := &opts{
		mask:      defaultMask,
		ownership: utils.CurrentFileOwner(),
	}
	for _, f := range optFuncs {
		f(o)
	}
	return o
}
