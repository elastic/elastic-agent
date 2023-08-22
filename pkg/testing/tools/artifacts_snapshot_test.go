package tools

import (
	"context"
	"path/filepath"
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

func TestBatchDownload(t *testing.T) {
	ctx := context.Background()

	packageRequests := make([]PackageRequest, 0)
	packageRequests = append(packageRequests, PackageRequest{
		Name:       "auditbeat-8.10.0-SNAPSHOT-aarch64.rpm",
		TargetPath: filepath.Join("build", "distributions", "elastic-agent-drop", "auditbeat-8.10.0-SNAPSHOT-aarch64.rpm"),
	})
	artifactSnapshotClient := NewArtifactSnapshotClient()
	err := artifactSnapshotClient.DownloadPackages(ctx, packageRequests, "8.10.0-SNAPSHOT")

	assert.NoError(t, err)
}
