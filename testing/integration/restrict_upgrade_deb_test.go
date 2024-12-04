//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/stretchr/testify/require"
)

func TestRestrictUpgradeDeb(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Deb,
		Stack: &define.Stack{},
		Sudo:  true,
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "ubuntu",
			},
		},
	})
	t.Run("when agent is deployed via deb, a user should not be able to upgrade the agent using the cli", func(t *testing.T) {
		ctx := context.Background()

		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat("deb"))
		require.NoError(t, err)
		installOpts := atesting.InstallOpts{
			NonInteractive: true,
			Privileged:     true,
			Force:          true,
		}

		_, err = fixture.InstallWithoutEnroll(ctx, &installOpts)
		require.NoError(t, err)

		require.Eventuallyf(t, func() bool {
			err = fixture.IsHealthy(ctx)
			return err == nil
		}, 5*time.Minute, time.Second,
			"Elastic-Agent did not report healthy. Agent status error: \"%v\"",
			err,
		)

		out, err := fixture.Exec(ctx, []string{"upgrade", "1.0.0"})
		require.Error(t, err)
		require.Contains(t, string(out), coordinator.ErrNotUpgradable.Error())
	})
}
