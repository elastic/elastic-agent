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

	actual, err := DetermineBatches("testdata", "batch_test")
	require.NoError(t, err)
	require.EqualValues(t, expected, actual)
}
