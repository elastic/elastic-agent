package componenttest

import (
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent/internal/pkg/agent/program/spec"
	"github.com/elastic/elastic-agent/pkg/component"
)

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
				ProgramSpec: spec.Spec{},
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
				ProgramSpec: spec.Spec{},
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
				ProgramSpec: spec.Spec{},
			},
		},
	},
}

func init() {
	component.Supported = TestSet
	component.SupportedMap = make(map[string]component.Spec)
	for _, dt := range TestSet {
		for _, dp := range dt {
			component.SupportedMap[dp.Spec.CommandName()] = dp.Spec
		}
	}

}

func LoadComponents() (component.ComponentSet, error) {
	component.SpecSuffix = ".yml"
	_, testFile, _, _ := runtime.Caller(0)
	level := 3
	rootDir := testFile
	for i := 0; i <= level; i++ {
		rootDir = filepath.Dir(rootDir)
	}

	return component.LoadComponents(filepath.Join(rootDir, "specs"))
}
