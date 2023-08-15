// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package snapshot

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/http"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

type Verifier struct {
	verifier        download.Verifier
	versionOverride *agtversion.ParsedSemVer
}

// NewVerifier creates a downloader which first checks local directory
// and then fallbacks to remote if configured.
func NewVerifier(log *logger.Logger, config *artifact.Config, allowEmptyPgp bool, pgp []byte, versionOverride *agtversion.ParsedSemVer) (download.Verifier, error) {
	cfg, err := snapshotConfig(config, versionOverride)
	if err != nil {
		return nil, err
	}
	v, err := http.NewVerifier(log, cfg, allowEmptyPgp, pgp)
	if err != nil {
		return nil, errors.New(err, "failed to create snapshot verifier")
	}

	return &Verifier{
		verifier:        v,
		versionOverride: versionOverride,
	}, nil
}

// Verify checks the package from configured source.
func (e *Verifier) Verify(a artifact.Artifact, version string, skipDefaultPgp bool, pgpBytes ...string) error {
	return e.verifier.Verify(a, version, skipDefaultPgp, pgpBytes...)
}

func (e *Verifier) Reload(c *artifact.Config) error {
	reloader, ok := e.verifier.(artifact.ConfigReloader)
	if !ok {
		return nil
	}

	cfg, err := snapshotConfig(c, e.versionOverride)
	if err != nil {
		return errors.New(err, "snapshot.downloader: failed to generate snapshot config")
	}

	return reloader.Reload(cfg)
}
