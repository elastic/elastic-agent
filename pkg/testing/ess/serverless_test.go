package ess

import (
	"context"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/stretchr/testify/require"
)

func TestStartServerless(t *testing.T) {
	logp.DevelopmentSetup()
	clientHandle := NewServerlessClient("aws-eu-west-1", "observability", "dVhuaUw0Z0JLcGpvUzVkeWxFVkE6a2w3d3RtXzRUTEMzLTZhZTBBWW81dw==")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*240)
	defer cancel()

	req := ServerlessRequest{Name: "ingest-e2e-test", RegionID: "aws-eu-west-1"}
	_, err := clientHandle.DeployStack(ctx, req)
	require.NoError(t, err)

	t.Logf("Waiting...")
	isReady, err := clientHandle.DeploymentIsReady(ctx)
	require.NoError(t, err)
	require.True(t, isReady)

	require.NotEmpty(t, clientHandle.proj.Endpoints)
	require.NotEmpty(t, clientHandle.proj.Credentials)
	t.Logf("got endpoints: %#v", clientHandle.proj.Endpoints)
	t.Logf("got auth: %#v", clientHandle.proj.Credentials)

	err = clientHandle.DeleteDeployment()
	require.NoError(t, err)
}
