// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import "github.com/elastic/elastic-agent/pkg/component"

// browserHomeModifier keeps the browser and CA importer on the same home without
// affecting Agent or other components. The coordinator reapplies it on policy updates.
func browserHomeModifier(home string) component.ComponentsModifier {
	return func(comps []component.Component, _ map[string]interface{}) ([]component.Component, error) {
		for i, comp := range comps {
			if home == "" || comp.InputSpec == nil || comp.InputSpec.InputType != "synthetics/browser" || comp.InputSpec.Spec.Command == nil {
				continue
			}
			// Runtime specs are shared: copy the spec, command and environment before editing.
			spec := *comp.InputSpec
			command := *spec.Spec.Command
			command.Env = make([]component.CommandEnvSpec, 0, len(command.Env)+1)
			for _, env := range spec.Spec.Command.Env {
				if env.Name != "HOME" {
					command.Env = append(command.Env, env)
				}
			}
			command.Env = append(command.Env, component.CommandEnvSpec{Name: "HOME", Value: home})
			spec.Spec.Command = &command
			comps[i].InputSpec = &spec
		}
		return comps, nil
	}
}
