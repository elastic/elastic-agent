// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package downloads

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// BeatsCIArtifactsBase name of the bucket used to store the artifacts generated on Beats CI
const BeatsCIArtifactsBase = "beats-ci-artifacts"

// FleetCIArtifactsBase name of the bucket used to store the artifacts generated on FLeet CI
const FleetCIArtifactsBase = "fleet-ci-artifacts"

// BucketURLResolver interface to resolve URL for artifacts in a bucket
type BucketURLResolver interface {
	Resolve() (string, string, string)
}

// BeatsLegacyURLResolver resolver for legacy Beats projects, such as metricbeat, filebeat, etc
// The Elastic Agent must use the project resolver
type BeatsLegacyURLResolver struct {
	Bucket   string
	Beat     string
	Variant  string
	FileName string
}

// NewBeatsLegacyURLResolver creates a new resolver for Beats projects
// The Elastic Agent must use the project resolver
func NewBeatsLegacyURLResolver(beat string, fileName string, variant string) *BeatsLegacyURLResolver {
	return &BeatsLegacyURLResolver{
		Bucket:   BeatsCIArtifactsBase,
		Beat:     beat,
		FileName: fileName,
		Variant:  variant,
	}
}

// Resolve returns the bucket, prefix and object for Beats artifacts
func (r *BeatsLegacyURLResolver) Resolve() (string, string, string) {
	artifact := r.Beat
	fileName := r.FileName

	if strings.EqualFold(r.Variant, "ubi8") {
		artifact = strings.ReplaceAll(artifact, "-ubi8", "")
	}

	prefix := fmt.Sprintf("snapshots/%s", artifact)
	object := fileName

	ciSnapshotsFn := UseBeatsCISnapshots
	if strings.EqualFold(artifact, "elastic-agent") {
		ciSnapshotsFn = UseElasticAgentCISnapshots
	}

	// the commit SHA will identify univocally the artifact in the GCP storage bucket
	if ciSnapshotsFn() {
		prefix = fmt.Sprintf("commits/%s", GithubCommitSha1)
		object = artifact + "/" + fileName
	}

	log.WithFields(log.Fields{
		"beat":     r.Beat,
		"bucket":   r.Bucket,
		"fileName": r.FileName,
		"object":   object,
		"prefix":   prefix,
		"variant":  r.Variant,
	}).Debug("Resolving URL from Beats Legacy resolver")

	return r.Bucket, prefix, object
}

// BeatsURLResolver resolver for Beats projects, such as metricbeat, filebeat, etc
// The Elastic Agent must use the project resolver
type BeatsURLResolver struct {
	Bucket   string
	Beat     string
	Variant  string
	FileName string
}

// NewBeatsURLResolver creates a new resolver for Beats projects
// The Elastic Agent must use the project resolver
func NewBeatsURLResolver(beat string, fileName string, variant string) *BeatsURLResolver {
	return &BeatsURLResolver{
		Bucket:   BeatsCIArtifactsBase,
		Beat:     beat,
		FileName: fileName,
		Variant:  variant,
	}
}

// Resolve returns the bucket, prefix and object for Beats artifacts
func (r *BeatsURLResolver) Resolve() (string, string, string) {
	artifact := r.Beat
	fileName := r.FileName

	if strings.EqualFold(r.Variant, "ubi8") {
		artifact = strings.ReplaceAll(artifact, "-ubi8", "")
	}

	prefix := fmt.Sprintf("beats/snapshots/%s", artifact)
	object := fileName

	ciSnapshotsFn := UseBeatsCISnapshots
	if strings.EqualFold(artifact, "elastic-agent") {
		ciSnapshotsFn = UseElasticAgentCISnapshots
	}

	// the commit SHA will identify univocally the artifact in the GCP storage bucket
	if ciSnapshotsFn() {
		prefix = fmt.Sprintf("beats/commits/%s", GithubCommitSha1)
		object = artifact + "/" + fileName
	}

	log.WithFields(log.Fields{
		"beat":     r.Beat,
		"bucket":   r.Bucket,
		"fileName": r.FileName,
		"object":   object,
		"prefix":   prefix,
		"variant":  r.Variant,
	}).Debug("Resolving URL from Beats resolver")

	return r.Bucket, prefix, object
}

// ProjectURLResolver resolver for Elastic projects, such as elastic-agent, fleet-server, etc.
// The Elastic Agent and Fleet Server must use the project resolver
type ProjectURLResolver struct {
	Bucket   string
	Project  string
	FileName string
	Variant  string
}

// NewProjectURLResolver creates a new resolver for Elastic projects
// The Elastic Agent and Fleet Server must use the project resolver
func NewProjectURLResolver(bucketBase string, project string, fileName string, variant string) *ProjectURLResolver {
	return &ProjectURLResolver{
		Bucket:   bucketBase,
		Project:  project,
		FileName: fileName,
		Variant:  variant,
	}
}

// Resolve returns the bucket, prefix and object for Elastic artifacts
func (r *ProjectURLResolver) Resolve() (string, string, string) {
	artifact := r.Project

	if strings.EqualFold(r.Variant, "ubi8") {
		artifact = strings.ReplaceAll(artifact, "-ubi8", "")
	}

	prefix := fmt.Sprintf("%s/snapshots", artifact)

	ciSnapshotsFn := UseBeatsCISnapshots
	if strings.EqualFold(artifact, "elastic-agent") {
		ciSnapshotsFn = UseElasticAgentCISnapshots
	}

	// the commit SHA will identify univocally the artifact in the GCP storage bucket
	if ciSnapshotsFn() {
		prefix = fmt.Sprintf("%s/commits/%s", artifact, GithubCommitSha1)
	}

	log.WithFields(log.Fields{
		"bucket":  r.Bucket,
		"object":  r.FileName,
		"prefix":  prefix,
		"project": artifact,
	}).Info("Resolving URL from Project resolver")

	return r.Bucket, prefix, r.FileName
}
