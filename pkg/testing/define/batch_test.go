// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package define

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBatch(t *testing.T) {
	const pkgName = "github.com/elastic/elastic-agent/pkg/testing/define/testdata"

	darwinLocalTests := []BatchPackageTests{
		{
			Name: pkgName,
			Tests: []string{
				"TestAnyLocal",
				"TestDarwinLocal",
			},
		},
	}
	darwinSudoTests := []BatchPackageTests{
		{
			Name: pkgName,
			Tests: []string{
				"TestAnySudo",
				"TestDarwinSudo",
			},
		},
	}
	linuxLocalTests := []BatchPackageTests{
		{
			Name: pkgName,
			Tests: []string{
				"TestAnyLocal",
				"TestLinuxLocal",
			},
		},
	}
	linuxSudoTests := []BatchPackageTests{
		{
			Name: pkgName,
			Tests: []string{
				"TestAnySudo",
				"TestLinuxSudo",
			},
		},
	}
	windowsLocalTests := []BatchPackageTests{
		{
			Name: pkgName,
			Tests: []string{
				"TestAnyLocal",
				"TestWindowsLocal",
			},
		},
	}
	windowsSudoTests := []BatchPackageTests{
		{
			Name: pkgName,
			Tests: []string{
				"TestAnySudo",
				"TestWindowsSudo",
			},
		},
	}
	expected := []Batch{
		{
			OS: OS{
				Type: Darwin,
				Arch: AMD64,
			},
			Tests:     darwinLocalTests,
			SudoTests: darwinSudoTests,
		},
		{
			OS: OS{
				Type: Darwin,
				Arch: ARM64,
			},
			Tests:     darwinLocalTests,
			SudoTests: darwinSudoTests,
		},
		{
			OS: OS{
				Type: Linux,
				Arch: AMD64,
			},
			Tests:     linuxLocalTests,
			SudoTests: linuxSudoTests,
		},
		{
			OS: OS{
				Type:    Linux,
				Arch:    ARM64,
				Version: "20.04",
				Distro:  "ubuntu",
			},
			Stack: &Stack{
				Version: "8.8.0",
			},
			Tests: []BatchPackageTests{
				{
					Name: pkgName,
					Tests: []string{
						"TestAnyLocal",
						"TestLinuxLocal",
						"TestSpecificCombinationOne",
						"TestSpecificCombinationTwo",
						"TestSpecificCombinationWithCloud",
					},
				},
			},
			SudoTests: linuxSudoTests,
		},
		{
			OS: OS{
				Type: Windows,
				Arch: AMD64,
			},
			Tests:     windowsLocalTests,
			SudoTests: windowsSudoTests,
		},
		{
			OS: OS{
				Type: Darwin,
				Arch: AMD64,
			},
			Isolate: true,
			Tests: []BatchPackageTests{
				{
					Name: pkgName,
					Tests: []string{
						"TestAnyIsolate",
					},
				},
			},
		},
		{
			OS: OS{
				Type: Darwin,
				Arch: ARM64,
			},
			Isolate: true,
			Tests: []BatchPackageTests{
				{
					Name: pkgName,
					Tests: []string{
						"TestAnyIsolate",
					},
				},
			},
		},
		{
			OS: OS{
				Type: Linux,
				Arch: AMD64,
			},
			Isolate: true,
			Tests: []BatchPackageTests{
				{
					Name: pkgName,
					Tests: []string{
						"TestAnyIsolate",
					},
				},
			},
		},
		{
			OS: OS{
				Type: Linux,
				Arch: ARM64,
			},
			Isolate: true,
			Tests: []BatchPackageTests{
				{
					Name: pkgName,
					Tests: []string{
						"TestAnyIsolate",
					},
				},
			},
		},
		{
			OS: OS{
				Type: Windows,
				Arch: AMD64,
			},
			Isolate: true,
			Tests: []BatchPackageTests{
				{
					Name: pkgName,
					Tests: []string{
						"TestAnyIsolate",
					},
				},
			},
		},
		{
			OS: OS{
				Type: Darwin,
				Arch: AMD64,
			},
			Isolate: true,
			Tests: []BatchPackageTests{
				{
					Name: pkgName,
					Tests: []string{
						"TestDarwinIsolate",
					},
				},
			},
		},
		{
			OS: OS{
				Type: Darwin,
				Arch: ARM64,
			},
			Isolate: true,
			Tests: []BatchPackageTests{
				{
					Name: pkgName,
					Tests: []string{
						"TestDarwinIsolate",
					},
				},
			},
		},
		{
			OS: OS{
				Type: Linux,
				Arch: AMD64,
			},
			Isolate: true,
			Tests: []BatchPackageTests{
				{
					Name: pkgName,
					Tests: []string{
						"TestLinuxIsolate",
					},
				},
			},
		},
		{
			OS: OS{
				Type: Linux,
				Arch: ARM64,
			},
			Isolate: true,
			Tests: []BatchPackageTests{
				{
					Name: pkgName,
					Tests: []string{
						"TestLinuxIsolate",
					},
				},
			},
		},
		{
			OS: OS{
				Type: Windows,
				Arch: AMD64,
			},
			Isolate: true,
			Tests: []BatchPackageTests{
				{
					Name: pkgName,
					Tests: []string{
						"TestWindowsIsolate",
					},
				},
			},
		},
	}

	actual, err := DetermineBatches("testdata", "", "batch_test")
	require.NoError(t, err)
	require.EqualValues(t, expected, actual)
}

var testLinuxLocalTests = []string{"TestLinuxLocal"}

var testLinuxLocalBatch = []Batch{
	{
		OS: OS{
			Type: "linux",
			Arch: "amd64",
		},
		Tests: []BatchPackageTests{
			{
				Name:  "github.com/elastic/elastic-agent/pkg/testing/define/testdata",
				Tests: testLinuxLocalTests,
			},
		},
	},
	{
		OS: OS{
			Type: "linux",
			Arch: "arm64",
		},
		Tests: []BatchPackageTests{
			{
				Name:  "github.com/elastic/elastic-agent/pkg/testing/define/testdata",
				Tests: testLinuxLocalTests,
			},
		},
	},
}

func TestGoTestFlags(t *testing.T) {
	testcases := []struct {
		name     string
		flags    string
		expected []Batch
	}{
		{
			name:     "Run single test",
			flags:    "-run ^TestLinuxLocal$",
			expected: testLinuxLocalBatch,
		},
		{
			name:     "Run single test with short flag",
			flags:    "-run ^TestLinuxLocal$ -short",
			expected: testLinuxLocalBatch,
		},
		{
			name:     "specify non-existing test",
			flags:    "-run ^thisdoesnotexist$",
			expected: nil,
		},
		{
			name:     "specify multiple run flags - last one wins - no test",
			flags:    "-run ^TestLinuxLocal$ -run ^thisdoesnotexist$",
			expected: nil,
		},
		{
			name:     "specify multiple run flags - last one wins - TestLinuxLocal",
			flags:    "-run ^thisdoesnotexist$ -run ^TestLinuxLocal$",
			expected: testLinuxLocalBatch,
		},
		{
			name:     "count flag will not multiply the test entries in each batch",
			flags:    "-run ^TestLinuxLocal$ -count 2",
			expected: testLinuxLocalBatch,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := DetermineBatches("testdata", tc.flags, "batch_test")
			require.NoError(t, err)
			require.EqualValues(t, tc.expected, actual)
		})
	}

}
