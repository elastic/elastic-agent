// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package download

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/pkg/version"
)

// Downloader is an interface allowing download of an artifact
type Downloader interface {
	Download(ctx context.Context, a artifact.Artifact, version *version.ParsedSemVer) (string, error)
}
