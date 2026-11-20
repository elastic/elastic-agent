// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/component"
)

func TestBrowserHomeModifier(t *testing.T) {
	t.Setenv("HOME", "/agent-home")
	command := &component.CommandSpec{Env: []component.CommandEnvSpec{
		{Name: "KEEP", Value: "value"}, {Name: "HOME", Value: "/old-home"},
	}}
	browser := &component.InputRuntimeSpec{InputType: "synthetics/browser", Spec: component.InputSpec{Command: command}}
	http := &component.InputRuntimeSpec{InputType: "synthetics/http", Spec: component.InputSpec{Command: command}}
	modifier := browserHomeModifier("/browser-home")
	for range 2 { // Regenerating the model on a policy update must reapply the override.
		comps := []component.Component{{InputSpec: browser}, {InputSpec: http}, {}}
		got, err := modifier(comps, nil)
		require.NoError(t, err)
		want := []component.CommandEnvSpec{{Name: "KEEP", Value: "value"}, {Name: "HOME", Value: "/browser-home"}}
		assert.Equal(t, want, got[0].InputSpec.Spec.Command.Env)
		assert.Same(t, http, got[1].InputSpec)
		assert.Nil(t, got[2].InputSpec)
		assert.Equal(t, "/old-home", command.Env[1].Value, "shared spec must remain unchanged")
		got, err = modifier(got, nil)
		require.NoError(t, err)
		assert.Equal(t, want, got[0].InputSpec.Spec.Command.Env, "applying twice must not duplicate HOME")
	}
	assert.Equal(t, "/agent-home", os.Getenv("HOME"))
}
