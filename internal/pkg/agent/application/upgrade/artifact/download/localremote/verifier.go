// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package localremote

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/composed"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/fs"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/http"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/snapshot"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// NewVerifier creates a downloader which first checks local directory
// and then fallbacks to remote if configured.
func NewVerifier(log *logger.Logger, config *artifact.Config, pgp []byte) (download.Verifier, error) {
	verifiers := make([]download.Verifier, 0, 3)

	fsVer, err := fs.NewVerifier(log, config, pgp)
	if err != nil {
		return nil, err
	}
	verifiers = append(verifiers, fsVer)

	// if the current build is a snapshot we use this downloader to update to the latest snapshot of the same version
	// useful for testing with a snapshot version of fleet for example
	// try snapshot repo before official
	if release.Snapshot() {
		snapshotVerifier, err := snapshot.NewVerifier(log, config, pgp, nil)
		if err != nil {
			log.Error(err)
		} else {
			verifiers = append(verifiers, snapshotVerifier)
		}
	}

	remoteVer, err := http.NewVerifier(log, config, pgp)
	if err != nil {
		return nil, err
	}
	verifiers = append(verifiers, remoteVer)

	return composed.NewVerifier(log, verifiers...), nil
}
