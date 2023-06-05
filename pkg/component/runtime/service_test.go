package runtime

import (
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/pkg/component"

	"github.com/google/go-cmp/cmp"
)

func makeComponent(name string, config map[string]interface{}) (component.Component, error) {
	c := component.Component{
		Units: []component.Unit{
			{
				Type:   client.UnitTypeInput,
				Config: &proto.UnitExpectedConfig{Type: name},
			},
		},
		InputSpec: &component.InputRuntimeSpec{
			Spec: component.InputSpec{
				Name: name,
			},
		},
	}
	unitCfg, err := component.ExpectedConfig(config)
	if err != nil {
		return c, err
	}
	c.Units[0].Config = unitCfg
	return c, nil
}

func makeEndpointComponent(t *testing.T, config map[string]interface{}) component.Component {
	comp, err := makeComponent("endpoint", config)
	if err != nil {
		t.Fatal(err)
	}
	return comp
}

func compareCompsConfigs(t *testing.T, comp component.Component, cfg map[string]interface{}) {
	for _, unit := range comp.Units {
		if unit.Type == client.UnitTypeInput {
			unitCfgMap := unit.Config.Source.AsMap()
			diff := cmp.Diff(cfg, unitCfgMap)
			if diff != "" {
				t.Fatal(diff)
			}
		}
	}
}

func TestInjectSigned(t *testing.T) {
	signed := &component.Signed{
		Data:      "eyJAdGltZXN0YW1wIjoiMjAyMy0wNS0yMlQxNzoxOToyOC40NjNaIiwiZXhwaXJhdGlvbiI6IjIwMjMtMDYtMjFUMTc6MTk6MjguNDYzWiIsImFnZW50cyI6WyI3ZjY0YWI2NC1hNmM0LTQ2ZTMtODIyYS0zODUxZGVkYTJmY2UiXSwiYWN0aW9uX2lkIjoiNGYwODQ2MGYtMDE0Yy00ZDllLWJmOGEtY2FhNjQyNzRhZGU0IiwidHlwZSI6IlVORU5ST0xMIiwidHJhY2VwYXJlbnQiOiIwMC1iOTBkYTlmOGNjNzdhODk0OTc0ZWIxZTIzMGNmNjc2Yy1lOTNlNzk4YTU4ODg2MDVhLTAxIn0=",
		Signature: "MEUCIAxxsi9ff1zyV0+4fsJLqbP8Qb83tedU5iIFldtxEzEfAiEA0KUsrL7q+Fv7z6Boux3dY2P4emGi71jsMGanIZ552bM=",
	}

	tests := []struct {
		name    string
		cfg     map[string]interface{}
		signed  *component.Signed
		wantCfg map[string]interface{}
	}{
		{
			name:    "nil signed",
			cfg:     map[string]interface{}{},
			wantCfg: map[string]interface{}{},
		},
		{
			name:   "signed",
			cfg:    map[string]interface{}{},
			signed: signed,
			wantCfg: map[string]interface{}{
				"signed": map[string]interface{}{
					"data":      "eyJAdGltZXN0YW1wIjoiMjAyMy0wNS0yMlQxNzoxOToyOC40NjNaIiwiZXhwaXJhdGlvbiI6IjIwMjMtMDYtMjFUMTc6MTk6MjguNDYzWiIsImFnZW50cyI6WyI3ZjY0YWI2NC1hNmM0LTQ2ZTMtODIyYS0zODUxZGVkYTJmY2UiXSwiYWN0aW9uX2lkIjoiNGYwODQ2MGYtMDE0Yy00ZDllLWJmOGEtY2FhNjQyNzRhZGU0IiwidHlwZSI6IlVORU5ST0xMIiwidHJhY2VwYXJlbnQiOiIwMC1iOTBkYTlmOGNjNzdhODk0OTc0ZWIxZTIzMGNmNjc2Yy1lOTNlNzk4YTU4ODg2MDVhLTAxIn0=",
					"signature": "MEUCIAxxsi9ff1zyV0+4fsJLqbP8Qb83tedU5iIFldtxEzEfAiEA0KUsrL7q+Fv7z6Boux3dY2P4emGi71jsMGanIZ552bM=",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			newComp, err := injectSigned(makeEndpointComponent(t, tc.cfg), tc.signed)
			if err != nil {
				t.Fatal(err)
			}

			compareCompsConfigs(t, newComp, tc.wantCfg)
		})
	}

}

func TestResolveUninstallTokenArg(t *testing.T) {
	tests := []struct {
		name              string
		uninstallSpec     *component.ServiceOperationsCommandSpec
		uninstallToken    string
		wantUninstallSpec *component.ServiceOperationsCommandSpec
	}{
		{
			name: "nil uninstall spec",
		},
		{
			name: "no uninstall token",
			uninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr"},
			},
			wantUninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr"},
			},
		},
		{
			name: "with uninstall token arg and empty token value",
			uninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr", "--uninstall-token"},
			},
			wantUninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr"},
			},
		},
		{
			name: "with uninstall token arg and non-empty token value",
			uninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr", "--uninstall-token"},
			},
			uninstallToken: "EQo1ML2T95pdcH",
			wantUninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr", "--uninstall-token", "EQo1ML2T95pdcH"},
			},
		},
		{
			name: "with uninstall token args cap gt len",
			uninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: func() []string {
					args := make([]string, 0, 8)
					args = append(args, "uninstall", "--log", "stderr", "--uninstall-token")
					return args
				}(),
			},
			uninstallToken: "EQo1ML2T95pdcH",
			wantUninstallSpec: &component.ServiceOperationsCommandSpec{
				Args: []string{"uninstall", "--log", "stderr", "--uninstall-token", "EQo1ML2T95pdcH"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var originalUninstallSpec component.ServiceOperationsCommandSpec
			if tc.uninstallSpec != nil {
				originalUninstallSpec = *tc.uninstallSpec
			}
			spec := resolveUninstallTokenArg(tc.uninstallSpec, tc.uninstallToken)
			diff := cmp.Diff(tc.wantUninstallSpec, spec)
			if diff != "" {
				t.Fatal(diff)
			}

			// Test that the original spec was not changed
			if tc.uninstallSpec != nil {
				diff = cmp.Diff(originalUninstallSpec, *tc.uninstallSpec)
				if diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}
