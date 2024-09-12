// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package downloads

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBeatsLegacyURLResolver(t *testing.T) {
	beat := "metricbeat"
	defer func() { GithubRepository = "elastic-agent" }()

	t.Run("Fetching snapshots bucket for RPM package", func(t *testing.T) {
		resolver := NewBeatsLegacyURLResolver(beat, beat+"-"+testVersion+"-x86_64.rpm", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "snapshots/"+beat)
		assert.Equal(t, object, beat+"-"+testVersion+"-x86_64.rpm")
	})

	t.Run("Fetching snapshots bucket for DEB package", func(t *testing.T) {
		resolver := NewBeatsLegacyURLResolver(beat, beat+"-"+testVersion+"-amd64.deb", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "snapshots/"+beat)
		assert.Equal(t, object, beat+"-"+testVersion+"-amd64.deb")
	})

	t.Run("Fetching snapshots bucket for TAR package adds OS to fileName and object", func(t *testing.T) {
		resolver := NewBeatsLegacyURLResolver(beat, beat+"-"+testVersion+"-linux-x86_64.tar.gz", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "snapshots/"+beat)
		assert.Equal(t, object, beat+"-"+testVersion+"-linux-x86_64.tar.gz")
	})

	t.Run("Fetching commits bucket for RPM package", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		GithubRepository = "beats"
		defer func() {
			GithubCommitSha1 = ""
			GithubRepository = ""
		}()

		resolver := NewBeatsLegacyURLResolver(beat, beat+"-"+testVersion+"-x86_64.rpm", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "commits/0123456789")
		assert.Equal(t, object, beat+"/"+beat+"-"+testVersion+"-x86_64.rpm")
	})

	t.Run("Fetching commits bucket for DEB package", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		GithubRepository = "beats"
		defer func() {
			GithubCommitSha1 = ""
			GithubRepository = ""
		}()

		resolver := NewBeatsLegacyURLResolver(beat, beat+"-"+testVersion+"-amd64.deb", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "commits/0123456789")
		assert.Equal(t, object, beat+"/"+beat+"-"+testVersion+"-amd64.deb")
	})

	t.Run("Fetching commits bucket for TAR package adds OS to fileName and object", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		GithubRepository = "beats"
		defer func() {
			GithubCommitSha1 = ""
			GithubRepository = ""
		}()

		resolver := NewBeatsLegacyURLResolver(beat, beat+"-"+testVersion+"-linux-x86_64.tar.gz", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "commits/0123456789")
		assert.Equal(t, object, beat+"/"+beat+"-"+testVersion+"-linux-x86_64.tar.gz")
	})

	t.Run("Fetching commits bucket for ubi8 Docker image", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		GithubRepository = "beats"
		defer func() {
			GithubCommitSha1 = ""
			GithubRepository = ""
		}()

		resolver := NewBeatsLegacyURLResolver(beat, beat+"-ubi8-"+testVersion+"-linux-x86_64.tar.gz", "ubi8")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "commits/0123456789")
		assert.Equal(t, object, beat+"/"+beat+"-ubi8-"+testVersion+"-linux-x86_64.tar.gz")
	})
}

func TestBeatsURLResolver(t *testing.T) {
	beat := "metricbeat"
	defer func() { GithubRepository = "elastic-agent" }()

	t.Run("Fetching snapshots bucket for RPM package", func(t *testing.T) {
		resolver := NewBeatsURLResolver(beat, beat+"-"+testVersion+"-x86_64.rpm", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "beats/snapshots/"+beat)
		assert.Equal(t, object, beat+"-"+testVersion+"-x86_64.rpm")
	})

	t.Run("Fetching snapshots bucket for DEB package", func(t *testing.T) {
		resolver := NewBeatsURLResolver(beat, beat+"-"+testVersion+"-amd64.deb", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "beats/snapshots/"+beat)
		assert.Equal(t, object, beat+"-"+testVersion+"-amd64.deb")
	})

	t.Run("Fetching snapshots bucket for TAR package adds OS to fileName and object", func(t *testing.T) {
		resolver := NewBeatsURLResolver(beat, beat+"-"+testVersion+"-linux-x86_64.tar.gz", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "beats/snapshots/"+beat)
		assert.Equal(t, object, beat+"-"+testVersion+"-linux-x86_64.tar.gz")
	})

	t.Run("Fetching commits bucket for RPM package", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		GithubRepository = "beats"
		defer func() {
			GithubCommitSha1 = ""
			GithubRepository = ""
		}()

		resolver := NewBeatsURLResolver(beat, beat+"-"+testVersion+"-x86_64.rpm", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "beats/commits/0123456789")
		assert.Equal(t, object, beat+"/"+beat+"-"+testVersion+"-x86_64.rpm")
	})

	t.Run("Fetching commits bucket for DEB package", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		GithubRepository = "beats"
		defer func() {
			GithubCommitSha1 = ""
			GithubRepository = ""
		}()

		resolver := NewBeatsURLResolver(beat, beat+"-"+testVersion+"-amd64.deb", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "beats/commits/0123456789")
		assert.Equal(t, object, beat+"/"+beat+"-"+testVersion+"-amd64.deb")
	})

	t.Run("Fetching commits bucket for TAR package adds OS to fileName and object", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		GithubRepository = "beats"
		defer func() {
			GithubCommitSha1 = ""
			GithubRepository = ""
		}()

		resolver := NewBeatsURLResolver(beat, beat+"-"+testVersion+"-linux-x86_64.tar.gz", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "beats/commits/0123456789")
		assert.Equal(t, object, beat+"/"+beat+"-"+testVersion+"-linux-x86_64.tar.gz", "")
	})

	t.Run("Fetching commits bucket for ubi8 Docker image", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		GithubRepository = "beats"
		defer func() {
			GithubCommitSha1 = ""
			GithubRepository = ""
		}()

		resolver := NewBeatsURLResolver(beat, beat+"-ubi8-"+testVersion+"-linux-x86_64.tar.gz", "ubi8")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, "beats/commits/0123456789")
		assert.Equal(t, object, beat+"/"+beat+"-ubi8-"+testVersion+"-linux-x86_64.tar.gz")
	})
}

func TestProjectURLResolver(t *testing.T) {
	project := "elastic-agent"

	t.Run("Fetching snapshots bucket for RPM package", func(t *testing.T) {
		resolver := NewProjectURLResolver(BeatsCIArtifactsBase, project, project+"-"+testVersion+"-x86_64.rpm", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, project+"/snapshots")
		assert.Equal(t, object, project+"-"+testVersion+"-x86_64.rpm")
	})

	t.Run("Fetching snapshots bucket for DEB package", func(t *testing.T) {
		resolver := NewProjectURLResolver(BeatsCIArtifactsBase, project, project+"-"+testVersion+"-amd64.deb", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, project+"/snapshots")
		assert.Equal(t, object, project+"-"+testVersion+"-amd64.deb")
	})

	t.Run("Fetching snapshots bucket for TAR package adds OS to fileName and object", func(t *testing.T) {
		resolver := NewProjectURLResolver(BeatsCIArtifactsBase, project, project+"-"+testVersion+"-linux-x86_64.tar.gz", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, project+"/snapshots")
		assert.Equal(t, object, project+"-"+testVersion+"-linux-x86_64.tar.gz")
	})

	t.Run("Fetching commits bucket for RPM package", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		defer func() { GithubCommitSha1 = "" }()

		resolver := NewProjectURLResolver(BeatsCIArtifactsBase, project, project+"-"+testVersion+"-x86_64.rpm", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, project+"/commits/0123456789")
		assert.Equal(t, object, project+"-"+testVersion+"-x86_64.rpm")
	})

	t.Run("Fetching commits bucket for DEB package", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		defer func() { GithubCommitSha1 = "" }()

		resolver := NewProjectURLResolver(BeatsCIArtifactsBase, project, project+"-"+testVersion+"-amd64.deb", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, project+"/commits/0123456789")
		assert.Equal(t, object, project+"-"+testVersion+"-amd64.deb")
	})

	t.Run("Fetching Elastic Agent commits bucket for TAR package adds OS to fileName and object", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		defer func() { GithubCommitSha1 = "" }()

		resolver := NewProjectURLResolver(BeatsCIArtifactsBase, project, project+"-"+testVersion+"-linux-x86_64.tar.gz", "")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, project+"/commits/0123456789")
		assert.Equal(t, object, project+"-"+testVersion+"-linux-x86_64.tar.gz")
	})

	t.Run("Fetching Elastic Agent commits bucket for ubi8 Docker image", func(t *testing.T) {
		GithubCommitSha1 = "0123456789"
		defer func() { GithubCommitSha1 = "" }()

		resolver := NewProjectURLResolver(BeatsCIArtifactsBase, project, project+"-ubi8-"+testVersion+"-linux-x86_64.tar.gz", "ubi8")

		bucket, prefix, object := resolver.Resolve()

		assert.Equal(t, bucket, "beats-ci-artifacts")
		assert.Equal(t, prefix, project+"/commits/0123456789")
		assert.Equal(t, object, project+"-ubi8-"+testVersion+"-linux-x86_64.tar.gz")
	})
}
