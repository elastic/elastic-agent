package componenttest

import "github.com/elastic/elastic-agent/pkg/component"

var TestSet = component.ComponentSet{
	component.INPUT: []component.Component{
		{
			Type: component.INPUT,
			Name: "testinput",
			Spec: component.Spec{
				Name: "TestInput",
				Inputs: []component.InputSpec{
					{
						Name:      "filestream",
						Command:   &component.CommandSpec{},
						Platforms: []string{"windows"},
						Outputs:   []string{"shipper"},
					},
				},
			},
		},
	},
	component.OUTPUT: []component.Component{
		{
			Type: component.OUTPUT,
			Name: "testoutput",
			Spec: component.Spec{
				Name: "TestOutput",
				Outputs: []component.OutputSpec{
					{
						Name:      "shipper-lin",
						Platforms: []string{"linux"},
						Command:   &component.CommandSpec{},
					},
				},
			},
		},
		{
			Type: component.OUTPUT,
			Name: "testoutput",
			Spec: component.Spec{
				Name: "TestOutput",
				Outputs: []component.OutputSpec{
					{
						Name:      "shipper",
						Platforms: []string{"windows"},
						Command:   &component.CommandSpec{},
					},
				},
			},
		},
	},
}
