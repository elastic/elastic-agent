// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import "github.com/pkg/errors"

type ComponentSet map[ComponentType][]Component

var Supported ComponentSet       // TODO: remove later , change logic to use injected DPUs
var SupportedMap map[string]Spec // TODO: remove later , change logic to use injected DPUs

const fleetServerName = "fleet-server"

func LoadComponents(path string) (ComponentSet, error) {
	dps := make(map[ComponentType][]Component)
	dps[OUTPUT] = make([]Component, 0)
	dps[INPUT] = make([]Component, 0)
	dps[FLEET_SERVER] = make([]Component, 0)

	// load specs from location
	specs, err := ReadSpecs(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed loading specs")
	}

	for _, s := range specs {
		t := INPUT
		if len(s.Outputs) > 0 {
			t = OUTPUT
		} else if s.Name == fleetServerName {
			t = FLEET_SERVER
		}

		dp := Component{
			Type: t,
			Name: s.Name,
			Spec: s,
		}

		dps[t] = append(dps[t], dp)
	}

	Supported = dps
	SupportedMap = make(map[string]Spec)
	for _, dt := range dps {
		for _, dp := range dt {
			SupportedMap[dp.Spec.Command()] = dp.Spec
		}
	}
	return dps, nil
}

// DetectNeededDPUs provides a list of needed DPUs (those we need to run or keep running) based on current config.
func (dps *ComponentSet) DetectNeededDPUs(t ComponentType, config map[string]interface{}) ([]Component, error) {
	return nil, nil
}
