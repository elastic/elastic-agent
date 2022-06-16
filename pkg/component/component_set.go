// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"github.com/pkg/errors"
)

type ComponentSet map[string]Spec

var Supported ComponentSet // TODO: remove later , change logic to use injected DPUs

const FleetServerName = "fleet-server"

func LoadComponents(path string) (ComponentSet, error) {
	dps := make(ComponentSet)

	// load specs from location
	specs, err := ReadSpecs(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed loading specs")
	}

	for _, s := range specs {
		dps[s.Name] = s
	}

	Supported = dps
	return dps, nil
}
