package define

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		reqs *Requirements
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
						reqs: &Requirements{
							Group: "foo",
						},
					},
				},
			},
			discoveredYAML: `
darwin/amd64:
    platform:
        os: darwin
        arch: amd64
    os:
        "":
            groups:
                foo:
                    group_name: foo
                    tests:
                        Test_all_default_platforms:
                            test_name: Test_all_default_platforms
                            local: false
                            sudo: false
darwin/arm64:
    platform:
        os: darwin
        arch: arm64
    os:
        "":
            groups:
                foo:
                    group_name: foo
                    tests:
                        Test_all_default_platforms:
                            test_name: Test_all_default_platforms
                            local: false
                            sudo: false
linux/amd64:
    platform:
        os: linux
        arch: amd64
    os:
        "":
            groups:
                foo:
                    group_name: foo
                    tests:
                        Test_all_default_platforms:
                            test_name: Test_all_default_platforms
                            local: false
                            sudo: false
linux/arm64:
    platform:
        os: linux
        arch: arm64
    os:
        "":
            groups:
                foo:
                    group_name: foo
                    tests:
                        Test_all_default_platforms:
                            test_name: Test_all_default_platforms
                            local: false
                            sudo: false
windows/amd64:
    platform:
        os: windows
        arch: amd64
    os:
        "":
            groups:
                foo:
                    group_name: foo
                    tests:
                        Test_all_default_platforms:
                            test_name: Test_all_default_platforms
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
						reqs: &Requirements{
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
						reqs: &Requirements{
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
						reqs: &Requirements{
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
						reqs: &Requirements{
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
						reqs: &Requirements{
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
						reqs: &Requirements{
							Group: "foo",
							OS:    []OS{{Type: Linux, Distro: "Ubuntu", Version: "24.04"}},
						},
					},
					{
						n: &NamedThing{name: "Test_only_linux2"},
						reqs: &Requirements{
							Group: "bar",
							OS:    []OS{{Type: Linux, Distro: "Ubuntu", Version: "24.04"}},
						},
					},
					{
						n: &NamedThing{name: "Test_only_windows"},
						reqs: &Requirements{
							Group: "foo",
							OS:    []OS{{Type: Windows, Version: "Windows Server 2019"}},
						},
					},
					{
						n: &NamedThing{name: "Test_all_default_platforms"},
						reqs: &Requirements{
							Group: "foo",
						},
					},
					{
						n: &NamedThing{name: "Test_all_default_platforms_sudo"},
						reqs: &Requirements{
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
				assert.YAMLEq(t, tt.discoveredYAML, string(actualTestYaml))
			}
		})
	}
}
