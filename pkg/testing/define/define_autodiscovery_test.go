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
		name            string
		args            args
		discoveredTests map[TestPlatform]TestsByPlatform
		discoveredYAML  string
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
			discoveredTests: map[TestPlatform]TestsByPlatform{
				TestPlatform{OS: "darwin", Arch: "amd64"}: {
					Platform: TestPlatform{OS: "darwin", Arch: "amd64"},
					OperatingSystems: map[TestOS]TestByOS{
						TestOS{Name: "", Version: ""}: {
							OperatingSystem: TestOS{Name: "", Version: ""},
							Groups: map[string]TestGroup{
								"foo": {
									Name: "foo",
									Tests: map[string]TestMetadata{
										"Test_all_default_platforms": {
											Name:  "Test_all_default_platforms",
											Local: false,
											Sudo:  false,
										},
									},
								},
							},
						},
					},
				},
				TestPlatform{OS: "darwin", Arch: "arm64"}: {
					Platform: TestPlatform{OS: "darwin", Arch: "arm64"},
					OperatingSystems: map[TestOS]TestByOS{
						TestOS{Name: "", Version: ""}: {
							OperatingSystem: TestOS{Name: "", Version: ""},
							Groups: map[string]TestGroup{
								"foo": {
									Name: "foo",
									Tests: map[string]TestMetadata{
										"Test_all_default_platforms": {
											Name:  "Test_all_default_platforms",
											Local: false,
											Sudo:  false,
										},
									},
								},
							},
						},
					},
				},
				TestPlatform{OS: "linux", Arch: "amd64"}: {
					Platform: TestPlatform{OS: "linux", Arch: "amd64"},
					OperatingSystems: map[TestOS]TestByOS{
						TestOS{Name: "", Version: ""}: {
							OperatingSystem: TestOS{Name: "", Version: ""},
							Groups: map[string]TestGroup{
								"foo": {
									Name: "foo",
									Tests: map[string]TestMetadata{
										"Test_all_default_platforms": {
											Name:  "Test_all_default_platforms",
											Local: false,
											Sudo:  false,
										},
									},
								},
							},
						},
					},
				},
				TestPlatform{OS: "linux", Arch: "arm64"}: {
					Platform: TestPlatform{OS: "linux", Arch: "arm64"},
					OperatingSystems: map[TestOS]TestByOS{
						TestOS{Name: "", Version: ""}: {
							OperatingSystem: TestOS{Name: "", Version: ""},
							Groups: map[string]TestGroup{
								"foo": {
									Name: "foo",
									Tests: map[string]TestMetadata{
										"Test_all_default_platforms": {
											Name:  "Test_all_default_platforms",
											Local: false,
											Sudo:  false,
										},
									},
								},
							},
						},
					},
				},
				TestPlatform{OS: "windows", Arch: "amd64"}: {
					Platform: TestPlatform{OS: "windows", Arch: "amd64"},
					OperatingSystems: map[TestOS]TestByOS{
						TestOS{Name: "", Version: ""}: {
							OperatingSystem: TestOS{Name: "", Version: ""},
							Groups: map[string]TestGroup{
								"foo": {
									Name: "foo",
									Tests: map[string]TestMetadata{
										"Test_all_default_platforms": {
											Name:  "Test_all_default_platforms",
											Local: false,
											Sudo:  false,
										},
									},
								},
							},
						},
					},
				},
			},
			//discoveredYAML: `foo: bar`,
		},

		//	[]TestOS{
		//
		//		TestPlatform{OS: "darwin", Arch: "arm64"}:  {{Name: "", Version: ""}},
		//		TestPlatform{OS: "linux", Arch: "amd64"}:   {{Name: "", Version: ""}},
		//		TestPlatform{OS: "linux", Arch: "arm64"}:   {{Name: "", Version: ""}},
		//		TestPlatform{OS: "windows", Arch: "amd64"}: {{Name: "", Version: ""}},
		//	},
		//},
		//{
		//	name: "Only windows test",
		//	args: args{
		//		tests: []inputTest{
		//			{
		//				n: &NamedThing{name: "Test_only_windows"},
		//				reqs: &Requirements{
		//					Group: "foo",
		//					OS:    []OS{{Type: Windows}},
		//				},
		//			},
		//		},
		//	},
		//	discoveredTests: map[TestPlatform][]TestOS{
		//		TestPlatform{OS: "windows", Arch: ""}: {{Name: "windows", Version: ""}},
		//	},
		//},
		//{
		//	name: "Specific windows version test",
		//	args: args{
		//		tests: []inputTest{
		//			{
		//				n: &NamedThing{name: "Test_only_windows"},
		//				reqs: &Requirements{
		//					Group: "foo",
		//					OS:    []OS{{Type: Windows, Version: "Windows Server 2019"}},
		//				},
		//			},
		//		},
		//	},
		//	discoveredTests: map[TestPlatform][]TestOS{
		//		TestPlatform{OS: "windows", Arch: ""}: {{Name: "windows", Version: "Windows Server 2019"}},
		//	},
		//},
		//{
		//	name: "Generic linux test",
		//	args: args{
		//		tests: []inputTest{
		//			{
		//				n: &NamedThing{name: "Test_only_linux"},
		//				reqs: &Requirements{
		//					Group: "foo",
		//					OS:    []OS{{Type: Linux}},
		//				},
		//			},
		//		},
		//	},
		//
		//	discoveredTests: map[TestPlatform][]TestOS{
		//		TestPlatform{OS: "linux", Arch: ""}: {{Name: "", Version: ""}},
		//	},
		//},
		//{
		//	name: "Specific linux distro test",
		//	args: args{
		//		tests: []inputTest{
		//			{
		//				n: &NamedThing{name: "Test_only_linux"},
		//				reqs: &Requirements{
		//					Group: "foo",
		//					OS:    []OS{{Type: Linux, Distro: "Ubuntu"}},
		//				},
		//			},
		//		},
		//	},
		//	discoveredTests: map[TestPlatform][]TestOS{
		//		TestPlatform{OS: "linux", Arch: ""}: {{Name: "Ubuntu", Version: ""}},
		//	},
		//},
		//{
		//	name: "Specific linux distro and version test",
		//	args: args{
		//		tests: []inputTest{
		//			{
		//				n: &NamedThing{name: "Test_only_linux"},
		//				reqs: &Requirements{
		//					Group: "foo",
		//					OS:    []OS{{Type: Linux, Distro: "Ubuntu", Version: "24.04"}},
		//				},
		//			},
		//		},
		//	},
		//	discoveredTests: map[TestPlatform][]TestOS{
		//		TestPlatform{OS: "linux", Arch: ""}: {{Name: "Ubuntu", Version: "24.04"}},
		//	},
		//},
		//{
		//	name: "Mix multiple tests",
		//	args: args{
		//		tests: []inputTest{
		//			{
		//				n: &NamedThing{name: "Test_only_linux"},
		//				reqs: &Requirements{
		//					Group: "foo",
		//					OS:    []OS{{Type: Linux, Distro: "Ubuntu", Version: "24.04"}},
		//				},
		//			},
		//			{
		//				n: &NamedThing{name: "Test_only_windows"},
		//				reqs: &Requirements{
		//					Group: "foo",
		//					OS:    []OS{{Type: Windows, Version: "Windows Server 2019"}},
		//				},
		//			},
		//			{
		//				n: &NamedThing{name: "Test_all_default_platforms"},
		//				reqs: &Requirements{
		//					Group: "foo",
		//				},
		//			},
		//		},
		//	},
		//	discoveredTests: map[TestPlatform][]TestOS{
		//		TestPlatform{OS: "darwin", Arch: "amd64"}:  {{Name: "", Version: ""}},
		//		TestPlatform{OS: "darwin", Arch: "arm64"}:  {{Name: "", Version: ""}},
		//		TestPlatform{OS: "linux", Arch: ""}:        {{Name: "Ubuntu", Version: "24.04"}},
		//		TestPlatform{OS: "linux", Arch: "amd64"}:   {{Name: "", Version: ""}},
		//		TestPlatform{OS: "linux", Arch: "arm64"}:   {{Name: "", Version: ""}},
		//		TestPlatform{OS: "windows", Arch: ""}:      {{Name: "windows", Version: "Windows Server 2019"}},
		//		TestPlatform{OS: "windows", Arch: "amd64"}: {{Name: "", Version: ""}},
		//	},
		//},
	}
	for _, tt := range tests {
		// reset map between testcases
		InitAutodiscovery(nil)
		t.Run(tt.name, func(t *testing.T) {
			for _, ttarg := range tt.args.tests {
				discoverTest(ttarg.n, ttarg.reqs)
			}
			assert.Equal(t, tt.discoveredTests, testAutodiscovery)
			if tt.discoveredYAML != "" {
				actualTestYaml, err := DumpAutodiscoveryYAML()
				assert.NoError(t, err)
				assert.YAMLEq(t, tt.discoveredYAML, string(actualTestYaml))
			}
		})
	}
}
