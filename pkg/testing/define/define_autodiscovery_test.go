package define

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type NamedThing struct {
	name string
}

func (n *NamedThing) Name() string {
	return n.name
}

func Test_discoverTest(t *testing.T) {
	type inputTest struct {
		n    Named
		reqs Requirements
	}
	type args struct {
		tests []inputTest
	}
	tests := []struct {
		name           string
		args           args
		discoveredYAML string
	}{
		{
			name: "Default test",
			args: args{
				tests: []inputTest{
					{
						n: &NamedThing{name: "Test_all_default_platforms"},
						reqs: Requirements{
							Group: "foo",
						},
					},
				},
			},
			discoveredYAML: `
        - os_family: linux
          arch: arm64
          os: ""
          version: ""
          groups:
            - name: foo
              tests:
                - name: Test_all_default_platforms
                  metadata:
                    local: false
                    sudo: false
        - os_family: windows
          arch: amd64
          os: ""
          version: ""
          groups:
            - name: foo
              tests:
                - name: Test_all_default_platforms
                  metadata:
                    local: false
                    sudo: false
        - os_family: darwin
          arch: amd64
          os: ""
          version: ""
          groups:
            - name: foo
              tests:
                - name: Test_all_default_platforms
                  metadata:
                    local: false
                    sudo: false
        - os_family: darwin
          arch: arm64
          os: ""
          version: ""
          groups:
            - name: foo
              tests:
                - name: Test_all_default_platforms
                  metadata:
                    local: false
                    sudo: false
        - os_family: linux
          arch: amd64
          os: ""
          version: ""
          groups:
            - name: foo
              tests:
                - name: Test_all_default_platforms
                  metadata:
                    local: false
                    sudo: false
`,
		},

		{
			name: "Only windows test",
			args: args{
				tests: []inputTest{
					{
						n: &NamedThing{name: "Test_only_windows"},
						reqs: Requirements{
							Group: "foo",
							OS:    []OS{{Type: Windows}},
						},
					},
				},
			},
		},
		{
			name: "Specific windows version test",
			args: args{
				tests: []inputTest{
					{
						n: &NamedThing{name: "Test_only_windows"},
						reqs: Requirements{
							Group: "foo",
							OS:    []OS{{Type: Windows, Version: "Windows Server 2019"}},
						},
					},
				},
			},
		},
		{
			name: "Generic linux test",
			args: args{
				tests: []inputTest{
					{
						n: &NamedThing{name: "Test_only_linux"},
						reqs: Requirements{
							Group: "foo",
							OS:    []OS{{Type: Linux}},
						},
					},
				},
			},
		},
		{
			name: "Specific linux distro test",
			args: args{
				tests: []inputTest{
					{
						n: &NamedThing{name: "Test_only_linux"},
						reqs: Requirements{
							Group: "foo",
							OS:    []OS{{Type: Linux, Distro: "Ubuntu"}},
						},
					},
				},
			},
		},
		{
			name: "Specific linux distro and version test",
			args: args{
				tests: []inputTest{
					{
						n: &NamedThing{name: "Test_only_linux"},
						reqs: Requirements{
							Group: "foo",
							OS:    []OS{{Type: Linux, Distro: "Ubuntu", Version: "24.04"}},
						},
					},
				},
			},
		},
		{
			name: "Mix multiple tests with different groups",
			args: args{
				tests: []inputTest{
					{
						n: &NamedThing{name: "Test_only_linux"},
						reqs: Requirements{
							Group: "foo",
							OS:    []OS{{Type: Linux, Distro: "Ubuntu", Version: "24.04"}},
						},
					},
					{
						n: &NamedThing{name: "Test_only_linux2"},
						reqs: Requirements{
							Group: "bar",
							OS:    []OS{{Type: Linux, Distro: "Ubuntu", Version: "24.04"}},
						},
					},
					{
						n: &NamedThing{name: "Test_only_windows"},
						reqs: Requirements{
							Group: "foo",
							OS:    []OS{{Type: Windows, Version: "Windows Server 2019"}},
						},
					},
					{
						n: &NamedThing{name: "Test_all_default_platforms"},
						reqs: Requirements{
							Group: "foo",
						},
					},
					{
						n: &NamedThing{name: "Test_all_default_platforms_sudo"},
						reqs: Requirements{
							Group: "bar",
							Sudo:  true,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		// reset map between testcases
		InitAutodiscovery(nil)
		t.Run(tt.name, func(t *testing.T) {
			for _, ttarg := range tt.args.tests {
				discoverTest(ttarg.n, ttarg.reqs)
			}
			actualTestYaml, err := DumpAutodiscoveryYAML()
			t.Logf("Got autodiscovery YAML:\n%s\n", actualTestYaml)
			assert.NoError(t, err)
			if tt.discoveredYAML != "" {
				expected := []OutputRunner{}
				err = yaml.Unmarshal([]byte(tt.discoveredYAML), &expected)
				require.NoError(t, err, "Error unmarshalling expected YAML")
				actual := []OutputRunner{}
				err = yaml.Unmarshal(actualTestYaml, &actual)
				require.NoError(t, err, "Error unmarshalling actual YAML")
				assert.ElementsMatch(t, expected, actual, "Generated runners do not match expected ones")

			}
		})
	}
}
