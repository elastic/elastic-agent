// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package downloads

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/Jeffail/gabs/v2"
	"github.com/stretchr/testify/assert"
)

var artifact = "elastic-agent"
var testVersion = "BEATS_VERSION"
var ubi8VersionPrefix = artifact + "-ubi8-" + testVersion
var versionPrefix = artifact + "-" + testVersion

var testResourcesBasePath = path.Join(".", "_testresources")

const bucket = "beats-ci-artifacts"
const commits = "commits"
const snapshots = "snapshots"

var nextTokenParamJSON *gabs.Container
var commitsJSON *gabs.Container
var snapshotsJSON *gabs.Container

func init() {
	nextTokenParamContent, err := os.ReadFile(path.Join(testResourcesBasePath, "gcp", "nextPageParam.json"))
	if err != nil {
		os.Exit(1)
	}
	nextTokenParamJSON, _ = gabs.ParseJSON(nextTokenParamContent)

	commitsContent, err := os.ReadFile(path.Join(testResourcesBasePath, "gcp", "commits.json"))
	if err != nil {
		os.Exit(1)
	}
	commitsJSON, _ = gabs.ParseJSON(commitsContent)

	snapshotsContent, err := os.ReadFile(path.Join(testResourcesBasePath, "gcp", "snapshots.json"))
	if err != nil {
		os.Exit(1)
	}
	snapshotsJSON, _ = gabs.ParseJSON(snapshotsContent)
}

func TestBuildArtifactName(t *testing.T) {
	OS := "linux"
	version := testVersion

	t.Run("For Git commits in version", func(t *testing.T) {
		arch := "x86_64"
		extension := "rpm"
		expectedFileName := "elastic-agent-1.2.3-SNAPSHOT-x86_64.rpm"
		versionWithCommit := "1.2.3-abcdef-SNAPSHOT"

		artifactName := buildArtifactName(artifact, versionWithCommit, OS, arch, extension, false)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, versionWithCommit, OS, arch, "RPM", false)
		assert.Equal(t, expectedFileName, artifactName)
	})

	t.Run("For RPM (amd64)", func(t *testing.T) {
		arch := "x86_64"
		extension := "rpm"
		expectedFileName := versionPrefix + "-x86_64.rpm"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, false)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "RPM", false)
		assert.Equal(t, expectedFileName, artifactName)
	})
	t.Run("For RPM (arm64)", func(t *testing.T) {
		arch := "aarch64"
		extension := "rpm"
		expectedFileName := versionPrefix + "-aarch64.rpm"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, false)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "RPM", false)
		assert.Equal(t, expectedFileName, artifactName)
	})

	t.Run("For DEB (amd64)", func(t *testing.T) {
		arch := "amd64"
		extension := "deb"
		expectedFileName := versionPrefix + "-amd64.deb"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, false)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "DEB", false)
		assert.Equal(t, expectedFileName, artifactName)
	})
	t.Run("For DEB (arm64)", func(t *testing.T) {
		arch := "arm64"
		extension := "deb"
		expectedFileName := versionPrefix + "-arm64.deb"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, false)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "DEB", false)
		assert.Equal(t, expectedFileName, artifactName)
	})

	t.Run("For TAR (amd64)", func(t *testing.T) {
		arch := "x86_64"
		extension := "tar.gz"
		expectedFileName := versionPrefix + "-linux-x86_64.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, false)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", false)
		assert.Equal(t, expectedFileName, artifactName)
	})
	t.Run("For TAR (arm64)", func(t *testing.T) {
		arch := "arm64"
		extension := "tar.gz"
		expectedFileName := versionPrefix + "-linux-arm64.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, false)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", false)
		assert.Equal(t, expectedFileName, artifactName)
	})

	t.Run("For Docker from Elastic's repository (amd64)", func(t *testing.T) {
		GithubCommitSha1 = ""
		defer func() { GithubCommitSha1 = "" }()

		artifact = "elastic-agent"
		arch := "amd64"
		extension := "tar.gz"
		expectedFileName := versionPrefix + "-docker-image-linux-amd64.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})
	t.Run("For Docker from Elastic's repository (arm64)", func(t *testing.T) {
		GithubCommitSha1 = ""
		defer func() { GithubCommitSha1 = "" }()

		artifact = "elastic-agent"
		arch := "arm64"
		extension := "tar.gz"
		expectedFileName := versionPrefix + "-docker-image-linux-arm64.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})

	t.Run("For Docker UBI8 from Elastic's repository (amd64)", func(t *testing.T) {
		GithubCommitSha1 = ""
		defer func() { GithubCommitSha1 = "" }()

		artifact = "elastic-agent-ubi8"
		arch := "amd64"
		extension := "tar.gz"
		expectedFileName := ubi8VersionPrefix + "-docker-image-linux-amd64.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})
	t.Run("For Docker UBI8 from Elastic's repository (arm64)", func(t *testing.T) {
		GithubCommitSha1 = ""
		defer func() { GithubCommitSha1 = "" }()

		artifact = "elastic-agent-ubi8"
		arch := "arm64"
		extension := "tar.gz"
		expectedFileName := ubi8VersionPrefix + "-docker-image-linux-arm64.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})

	t.Run("For Docker from local repository (amd64)", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = "/tmp"

		artifact = "elastic-agent"
		arch := "amd64"
		extension := "tar.gz"
		expectedFileName := versionPrefix + "-docker-image-linux-amd64.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})
	t.Run("For Docker from local repository (arm64)", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = "/tmp"

		artifact = "elastic-agent"
		arch := "arm64"
		extension := "tar.gz"
		expectedFileName := versionPrefix + "-docker-image-linux-arm64.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})

	t.Run("For Docker UBI8 from local repository (amd64)", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = "/tmp"

		artifact = "elastic-agent-ubi8"
		arch := "amd64"
		extension := "tar.gz"
		expectedFileName := ubi8VersionPrefix + "-docker-image-linux-amd64.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})
	t.Run("For Docker UBI8 from local repository (arm64)", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = "/tmp"

		artifact = "elastic-agent-ubi8"
		arch := "arm64"
		extension := "tar.gz"
		expectedFileName := ubi8VersionPrefix + "-docker-image-linux-arm64.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})

	t.Run("For Docker from GCP (amd64)", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		defer func() { GithubCommitSha1 = "" }()

		artifact = "elastic-agent"
		arch := "amd64"
		extension := "tar.gz"
		expectedFileName := versionPrefix + "-linux-amd64.docker.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})
	t.Run("For Docker from GCP (arm64)", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		defer func() { GithubCommitSha1 = "" }()

		artifact = "elastic-agent"
		arch := "arm64"
		extension := "tar.gz"
		expectedFileName := versionPrefix + "-linux-arm64.docker.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})

	t.Run("For Docker UBI8 from GCP (amd64)", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		defer func() { GithubCommitSha1 = "" }()

		artifact = "elastic-agent-ubi8"
		arch := "amd64"
		extension := "tar.gz"
		expectedFileName := ubi8VersionPrefix + "-linux-amd64.docker.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})
	t.Run("For Docker UBI8 from GCP (arm64)", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		defer func() { GithubCommitSha1 = "" }()

		artifact = "elastic-agent-ubi8"
		arch := "arm64"
		extension := "tar.gz"
		expectedFileName := ubi8VersionPrefix + "-linux-arm64.docker.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})

	t.Run("For Docker for a Pull Request (amd64)", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		defer func() { GithubCommitSha1 = "" }()

		artifact = "elastic-agent"
		arch := "amd64"
		extension := "tar.gz"
		expectedFileName := versionPrefix + "-linux-amd64.docker.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})
	t.Run("For Docker for a Pull Request (arm64)", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		defer func() { GithubCommitSha1 = "" }()

		artifact = "elastic-agent"
		arch := "arm64"
		extension := "tar.gz"
		expectedFileName := versionPrefix + "-linux-arm64.docker.tar.gz"

		artifactName := buildArtifactName(artifact, version, OS, arch, extension, true)
		assert.Equal(t, expectedFileName, artifactName)

		artifactName = buildArtifactName(artifact, version, OS, arch, "TAR.GZ", true)
		assert.Equal(t, expectedFileName, artifactName)
	})
}

func TestCheckPRVersion(t *testing.T) {
	var testVersion = "BEATS_VERSION"

	t.Run("Checking a version should return the version", func(t *testing.T) {
		v := CheckPRVersion(testVersion, testVersion)

		assert.Equal(t, testVersion, v)
	})

	t.Run("A Commit-based version should return base version", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		defer func() { GithubCommitSha1 = "" }()

		v := CheckPRVersion(testVersion, testVersion)

		assert.Equal(t, testVersion, v)
	})
}

func TestFetchBeatsBinaryFromLocalPath(t *testing.T) {
	artifact := "elastic-agent"
	beatsDir := path.Join(testResourcesBasePath, "beats")
	version := testVersion

	ctx := context.Background()

	t.Run("Fetching non-existent binary from local Beats dir throws an error", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		_, err := FetchBeatsBinary(ctx, "foo_fileName", artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
	})

	t.Run("Fetching RPM binary (amd64) from local Beats dir", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		artifactName := versionPrefix + "-x86_64.rpm"

		downloadedFilePath, err := FetchBeatsBinary(ctx, artifactName, artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
		assert.Equal(t, downloadedFilePath, "")
	})
	t.Run("Fetching RPM binary (arm64) from local Beats dir", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		artifactName := versionPrefix + "-aarch64.rpm"

		downloadedFilePath, err := FetchBeatsBinary(ctx, artifactName, artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
		assert.Equal(t, downloadedFilePath, "")
	})

	t.Run("Fetching DEB binary (amd64) from local Beats dir", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		artifactName := versionPrefix + "-amd64.deb"

		downloadedFilePath, err := FetchBeatsBinary(ctx, artifactName, artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
		assert.Equal(t, downloadedFilePath, "")
	})
	t.Run("Fetching DEB binary (arm64) from local Beats dir", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		artifactName := versionPrefix + "-arm64.deb"

		downloadedFilePath, err := FetchBeatsBinary(ctx, artifactName, artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
		assert.Equal(t, downloadedFilePath, "")
	})

	t.Run("Fetching TAR binary (amd64) from local Beats dir", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		artifactName := versionPrefix + "-linux-amd64.tar.gz"

		downloadedFilePath, err := FetchBeatsBinary(ctx, artifactName, artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
		assert.Equal(t, downloadedFilePath, "")
	})
	t.Run("Fetching TAR binary (x86_64) from local Beats dir", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		artifactName := versionPrefix + "-linux-x86_64.tar.gz"

		downloadedFilePath, err := FetchBeatsBinary(ctx, artifactName, artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
		assert.Equal(t, downloadedFilePath, "")
	})
	t.Run("Fetching TAR binary (arm64) from local Beats dir", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		artifactName := versionPrefix + "-linux-arm64.tar.gz"

		downloadedFilePath, err := FetchBeatsBinary(ctx, artifactName, artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
		assert.Equal(t, downloadedFilePath, "")
	})

	t.Run("Fetching Docker binary (amd64) from local Beats dir", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		artifactName := versionPrefix + "-linux-amd64.docker.tar.gz"

		downloadedFilePath, err := FetchBeatsBinary(ctx, artifactName, artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
		assert.Equal(t, downloadedFilePath, "")
	})
	t.Run("Fetching Docker binary (arm64) from local Beats dir", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		artifactName := versionPrefix + "-linux-arm64.docker.tar.gz"

		downloadedFilePath, err := FetchBeatsBinary(ctx, artifactName, artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
		assert.Equal(t, downloadedFilePath, "")
	})

	t.Run("Fetching ubi8 Docker binary (amd64) from local Beats dir", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		artifactName := ubi8VersionPrefix + "-linux-amd64.docker.tar.gz"

		downloadedFilePath, err := FetchBeatsBinary(ctx, artifactName, artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
		assert.Equal(t, downloadedFilePath, "")
	})
	t.Run("Fetching ubi8 Docker binary (arm64) from local Beats dir", func(t *testing.T) {
		defer func() { BeatsLocalPath = "" }()
		BeatsLocalPath = beatsDir

		artifactName := ubi8VersionPrefix + "-linux-arm64.docker.tar.gz"

		downloadedFilePath, err := FetchBeatsBinary(ctx, artifactName, artifact, version, timeoutFactor, true, "", false)
		assert.NotNil(t, err)
		assert.Equal(t, downloadedFilePath, "")
	})
}

func Test_IsAlias(t *testing.T) {
	t.Run("From not an alias", func(t *testing.T) {
		assert.False(t, IsAlias("1.2.3-SNAPSHOT"), "Version should not be an alias")
	})

	t.Run("From an alias", func(t *testing.T) {
		assert.True(t, IsAlias("1.2-SNAPSHOT"), "Version should be an alias")
	})
}

func Test_NewElasticVersion(t *testing.T) {
	t.Run("newElasticVersion without git commit", func(t *testing.T) {
		v := newElasticVersion("1.2.3-SNAPSHOT")

		assert.Equal(t, "1.2.3", v.Version, "Version should not include SNAPSHOT nor commit")
		assert.Equal(t, "1.2.3-SNAPSHOT", v.FullVersion, "Full version should include SNAPSHOT")
		assert.Equal(t, "1.2.3", v.HashedVersion, "Hashed version should not include SNAPSHOT")
		assert.Equal(t, "1.2.3-SNAPSHOT", v.SnapshotVersion, "Snapshot version should include SNAPSHOT")
	})

	t.Run("newElasticVersion with git commit", func(t *testing.T) {
		v := newElasticVersion("1.2.3-abcdef-SNAPSHOT")

		assert.Equal(t, "1.2.3", v.Version, "Version should not include SNAPSHOT nor commit")
		assert.Equal(t, "1.2.3-abcdef-SNAPSHOT", v.FullVersion, "Full version should include commit and SNAPSHOT")
		assert.Equal(t, "1.2.3-abcdef", v.HashedVersion, "Hashed version should include commit but no SNAPSHOT")
		assert.Equal(t, "1.2.3-SNAPSHOT", v.SnapshotVersion, "Snapshot version should include SNAPSHOT but no commit")
	})
}

func TestGetBucketSearchNextPageParam_HasMorePages(t *testing.T) {
	expectedParam := "&pageToken=foo"

	param := getBucketSearchNextPageParam(nextTokenParamJSON)
	assert.True(t, param == expectedParam)
}

func TestGetBucketSearchNextPageParam_HasNoMorePages(t *testing.T) {
	// this JSON file does not contain the tokken field
	param := getBucketSearchNextPageParam(commitsJSON)
	assert.True(t, param == "")
}

func Test_GetCommitVersion(t *testing.T) {
	t.Run("GetCommitVersion without git commit", func(t *testing.T) {
		v := GetCommitVersion("1.2.3-SNAPSHOT")

		assert.Equal(t, "1.2.3", v, "Version should not include SNAPSHOT nor commit")
	})

	t.Run("GetCommitVersion with git commit", func(t *testing.T) {
		v := GetCommitVersion("1.2.3-abcdef-SNAPSHOT")

		assert.Equal(t, "1.2.3-abcdef", v, "Version should not include SNAPSHOT nor commit")
	})
}

func Test_GetFullVersion(t *testing.T) {
	t.Run("GetFullVersion without git commit", func(t *testing.T) {
		v := GetFullVersion("1.2.3-SNAPSHOT")

		assert.Equal(t, "1.2.3-SNAPSHOT", v, "Version should not include SNAPSHOT nor commit")
	})

	t.Run("GetFullVersion with git commit", func(t *testing.T) {
		v := GetFullVersion("1.2.3-abcdef-SNAPSHOT")

		assert.Equal(t, "1.2.3-abcdef-SNAPSHOT", v, "Version should not include SNAPSHOT nor commit")
	})
}

func Test_GetSnapshotVersion(t *testing.T) {
	t.Run("GetSnapshotVersion without git commit", func(t *testing.T) {
		v := GetSnapshotVersion("1.2.3-SNAPSHOT")

		assert.Equal(t, "1.2.3-SNAPSHOT", v, "Version should include SNAPSHOT but no commit")
	})

	t.Run("GetCommitVersion with git commit", func(t *testing.T) {
		v := GetSnapshotVersion("1.2.3-abcdef-SNAPSHOT")

		assert.Equal(t, "1.2.3-SNAPSHOT", v, "Version should include SNAPSHOT but no commit")
	})
}

func Test_GetVersion(t *testing.T) {
	t.Run("GetVersion without git commit", func(t *testing.T) {
		v := GetVersion("1.2.3-SNAPSHOT")

		assert.Equal(t, "1.2.3", v, "Version should not include SNAPSHOT nor commit")
	})

	t.Run("GetVersion with git commit", func(t *testing.T) {
		v := GetVersion("1.2.3-abcdef-SNAPSHOT")

		assert.Equal(t, "1.2.3", v, "Version should not include SNAPSHOT nor commit")
	})
}

func TestProcessBucketSearchPage_CommitFound(t *testing.T) {
	// retrieving last element in commits.json
	object := "024b732844d40bdb2bf806480af2b03fcb8fbdbe/elastic-agent/" + versionPrefix + "-darwin-x86_64.tar.gz"

	mediaLink, err := processBucketSearchPage(commitsJSON, 1, bucket, commits, object)
	assert.Nil(t, err)
	assert.True(t, mediaLink == "https://storage.googleapis.com/download/storage/v1/b/beats-ci-artifacts/o/commits%2F024b732844d40bdb2bf806480af2b03fcb8fbdbe%2Felastic-agent%2F"+versionPrefix+"-darwin-x86_64.tar.gz?generation=1612983859986704&alt=media")
}

func TestProcessBucketSearchPage_CommitsNotFound(t *testing.T) {
	object := "foo/" + versionPrefix + "-linux-amd64.docker.tar.gz"

	mediaLink, err := processBucketSearchPage(commitsJSON, 1, bucket, commits, object)
	assert.NotNil(t, err)
	assert.True(t, mediaLink == "")
}

func TestProcessBucketSearchPage_SnapshotsFound(t *testing.T) {
	// retrieving last element in snapshots.json
	object := "filebeat/filebeat-oss-7.10.2-SNAPSHOT-arm64.deb"

	mediaLink, err := processBucketSearchPage(snapshotsJSON, 1, bucket, snapshots, object)
	assert.Nil(t, err)
	assert.True(t, mediaLink == "https://storage.googleapis.com/download/storage/v1/b/beats-ci-artifacts/o/snapshots%2Ffilebeat%2Ffilebeat-oss-7.10.2-SNAPSHOT-arm64.deb?generation=1610629747796392&alt=media")
}

func TestProcessBucketSearchPage_SnapshotsNotFound(t *testing.T) {
	object := "filebeat/filebeat-oss-7.12.2-SNAPSHOT-arm64.deb"

	mediaLink, err := processBucketSearchPage(snapshotsJSON, 1, bucket, snapshots, object)
	assert.NotNil(t, err)
	assert.True(t, mediaLink == "")
}

func TestRemoveCommitFromSnapshot(t *testing.T) {
	assert.Equal(t, "elastic-agent-8.0.0-SNAPSHOT-darwin-x86_64.tar.gz", RemoveCommitFromSnapshot("elastic-agent-8.0.0-abcdef-SNAPSHOT-darwin-x86_64.tar.gz"))
	assert.Equal(t, "8.0.0-SNAPSHOT", RemoveCommitFromSnapshot("8.0.0-a12345-SNAPSHOT"))
	assert.Equal(t, "7.14.x-SNAPSHOT", RemoveCommitFromSnapshot("7.14.x-a12345-SNAPSHOT"))
	assert.Equal(t, "8.0.0-SNAPSHOT", RemoveCommitFromSnapshot("8.0.0-SNAPSHOT"))
	assert.Equal(t, "7.14.x-SNAPSHOT", RemoveCommitFromSnapshot("7.14.x-SNAPSHOT"))
}

func TestSnapshotHasCommit(t *testing.T) {
	t.Run("Returns true with commits in snapshots", func(t *testing.T) {
		assert.True(t, SnapshotHasCommit("8.0.0-a12345-SNAPSHOT"))
	})

	t.Run("Returns false with commits in snapshots", func(t *testing.T) {
		assert.False(t, SnapshotHasCommit("7.14.x-SNAPSHOT"))
		assert.False(t, SnapshotHasCommit("8.0.0-SNAPSHOT"))
	})
}

func TestGetEnv(t *testing.T) {
	t.Run("Empty value should return fallback", func(t *testing.T) {
		defer os.Unsetenv("test.key")
		os.Setenv("test.key", "")

		val := getEnv("test.key", "fallback")
		assert.Equal(t, "fallback", val)
	})

	t.Run("Non existing key should return fallback", func(t *testing.T) {
		val := getEnv("test.key", "fallback")
		assert.Equal(t, "fallback", val)
	})

	t.Run("Value should return value", func(t *testing.T) {
		defer os.Unsetenv("test.key")
		os.Setenv("test.key", "value")

		val := getEnv("test.key", "fallback")
		assert.Equal(t, "value", val)
	})
}
