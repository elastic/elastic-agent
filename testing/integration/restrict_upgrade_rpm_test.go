//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/stretchr/testify/require"
)

func TestRestrictUpgradeRPM(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: RPM,
		Stack: &define.Stack{},
		Sudo:  true,
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "rhel",
			},
		},
	})
	t.Run("when agent is deployed via rpm, a user should not be able to upgrade the agent using the cli", func(t *testing.T) {
		ctx := context.Background()

		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat("rpm"))
		require.NoError(t, err)
		installOpts := atesting.InstallOpts{
			NonInteractive: true,
			Privileged:     true,
			Force:          true,
			DelayEnroll:    true,
		}

		_, err = fixture.Install(ctx, &installOpts)
		require.NoError(t, err)
		out, err := fixture.Exec(ctx, []string{"upgrade", "1.0.0"})
		require.Error(t, err)
		require.Contains(t, string(out), cmd.UpgradeDisabledError.Error())
	})
}
