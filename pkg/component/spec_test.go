// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpec_Validation(t *testing.T) {
	scenarios := []struct {
		Name    string
		Spec    string
		Err     string
		CheckFn func(t *testing.T, spec Spec)
	}{
		{
			Name: "Empty",
			Spec: "",
			Err:  "missing required field accessing 'version'",
		},
		{
			Name: "Bad Version",
			Spec: "version: 1",
			Err:  "only version 2 is allowed accessing config",
		},
		{
			Name: "No Command or Service",
			Spec: `
        version: 2
        inputs:
          - name: testing
            description: Testing Input
            platforms:
              - linux/amd64
            outputs:
              - elasticsearch
        `,
			Err: "input 'testing' must define either command or service accessing 'inputs.0'",
		},
		{
			Name: "Duplicate Platform",
			Spec: `
        version: 2
        inputs:
          - name: testing
            description: Testing Input
            platforms:
              - linux/amd64
              - linux/amd64
            outputs:
              - elasticsearch
            command: {}
        `,
			Err: "input 'testing' defines the platform 'linux/amd64' more than once accessing 'inputs.0'",
		},
		{
			Name: "Unknown Platform",
			Spec: `
        version: 2
        inputs:
          - name: testing
            description: Testing Input
            platforms:
              - unknown/amd64
            outputs:
              - elasticsearch
            command: {}
        `,
			Err: "input 'testing' defines an unknown platform 'unknown/amd64' accessing 'inputs.0'",
		},
		{
			Name: "Duplicate Output",
			Spec: `
        version: 2
        inputs:
          - name: testing
            description: Testing Input
            platforms:
              - linux/amd64
            outputs:
              - elasticsearch
              - elasticsearch
            command: {}
        `,
			Err: "input 'testing' defines the output 'elasticsearch' more than once accessing 'inputs.0'",
		},
		{
			Name: "Duplicate Platform Same Input Name",
			Spec: `
        version: 2
        inputs:
          - name: testing
            description: Testing Input
            platforms:
              - linux/amd64
            outputs:
              - elasticsearch
            command: {}
          - name: testing
            description: Testing Input
            platforms:
              - linux/amd64
            outputs:
              - elasticsearch
            command: {}
        `,
			Err: "input 'testing' at inputs.1 defines the same platform as a previous definition accessing config",
		},
		{
			Name: "Valid",
			Spec: `
        version: 2
        inputs:
          - name: testing
            description: Testing Input
            platforms:
              - linux/amd64
              - windows/amd64
            outputs:
              - elasticsearch
            command: {}
          - name: testing
            description: Testing Input
            platforms:
              - darwin/amd64
            outputs:
              - elasticsearch
            service:
              name: "co.elastic.endpoint"
              cport: 6788
              csocket: ".test.sock"
              operations:
                install:
                  args: ["install"]
                uninstall:
                  args: ["uninstall"]
    `,
			Err: "",
			CheckFn: func(t *testing.T, spec Spec) {
				assert.Equal(t, spec.Inputs[1].Service.CPort, 6788)
				assert.Equal(t, spec.Inputs[1].Service.CSocket, ".test.sock")
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			spec, err := LoadSpec([]byte(scenario.Spec))
			if scenario.Err != "" {
				require.Error(t, err)
				assert.Equal(t, scenario.Err, err.Error())
			} else {
				require.NoError(t, err)
				if scenario.CheckFn != nil {
					scenario.CheckFn(t, spec)
				}
			}
		})
	}
}
