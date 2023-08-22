package tools

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArtifactsSnapshotManifest(t *testing.T) {

	snapshotClient := NewArtifactSnapshotClient()
	resp, err := snapshotClient.getManifestResponse(context.Background(), "8.10.0-SNAPSHOT")
	assert.NoError(t, err)

	t.Logf("resp: %+v\n", resp)

}

func TestArtifactsSnapshotProjects(t *testing.T) {
	ctx := context.Background()
	snapshotClient := NewArtifactSnapshotClient()
	resp, err := snapshotClient.getManifestResponse(ctx, "8.10.0-SNAPSHOT")
	assert.NoError(t, err)
	packageMap, err := snapshotClient.getManifestPackages(ctx, resp.ManifestURL)
	assert.NoError(t, err)
	t.Logf("packageMap: %+v\n", packageMap)
	t.Log("------------------")
	t.Log(packageMap["auditbeat-8.10.0-SNAPSHOT-aarch64.rpm"])
	t.Log("------------------")
	t.Log(packageMap["auditbeat-8.10.0-SNAPSHOT-aarch64.rpm"].Url)

}
