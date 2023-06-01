package runtime

import (
	"testing"

	"github.com/elastic/elastic-agent/pkg/component"

	"github.com/google/go-cmp/cmp"
)

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
