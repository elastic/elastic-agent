// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipelines

import (
	"github.com/elastic/elastic-agent/dev-tools/buildkite/pipeline"
)

// GCECleanup generates the pipeline.elastic-agent-gce-cleanup.yml pipeline.
// This pipeline removes stale GCE instances having matching labels, name prefixes
// and older than 24 hours.
func GCECleanup() *pipeline.Pipeline {
	step := pipeline.CommandWithKey("GCE Cleanup", "gce-cleanup", ".buildkite/scripts/steps/gce-cleanup.sh")
	pipeline.SetAgent(step, pipeline.Agent{
		"provider": "gcp",
	})

	return pipeline.New().
		Env("VAULT_PATH", pipeline.VaultPathGCP).
		Add(step)
}
