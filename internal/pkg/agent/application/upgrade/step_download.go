// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	download2 "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	composed2 "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/composed"
	fs2 "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/fs"
	http2 "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/http"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/localremote"
	snapshot2 "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/snapshot"

	"go.elastic.co/apm"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func (u *Upgrader) downloadArtifact(ctx context.Context, version, sourceURI string) (_ string, err error) {
	span, ctx := apm.StartSpan(ctx, "downloadArtifact", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()
	// do not update source config
	settings := *u.settings
	if sourceURI != "" {
		if strings.HasPrefix(sourceURI, "file://") {
			// update the DropPath so the fs.Downloader can download from this
			// path instead of looking into the installed downloads directory
			settings.DropPath = strings.TrimPrefix(sourceURI, "file://")
		} else {
			settings.SourceURI = sourceURI
		}
	}

	verifier, err := newVerifier(version, u.log, &settings)
	if err != nil {
		return "", errors.New(err, "initiating verifier")
	}

	fetcher, err := newDownloader(version, u.log, &settings)
	if err != nil {
		return "", errors.New(err, "initiating fetcher")
	}

	path, err := fetcher.Download(ctx, agentArtifact, version)
	if err != nil {
		return "", errors.New(err, "failed upgrade of agent binary")
	}

	if err := verifier.Verify(agentArtifact, version); err != nil {
		return "", errors.New(err, "failed verification of agent binary")
	}

	return path, nil
}

func newDownloader(version string, log *logger.Logger, settings *artifact.Config) (download2.Downloader, error) {
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		return localremote.NewDownloader(log, settings)
	}

	// try snapshot repo before official
	snapDownloader, err := snapshot2.NewDownloader(log, settings, version)
	if err != nil {
		return nil, err
	}

	httpDownloader, err := http2.NewDownloader(log, settings)
	if err != nil {
		return nil, err
	}

	return composed2.NewDownloader(fs2.NewDownloader(settings), snapDownloader, httpDownloader), nil
}

func newVerifier(version string, log *logger.Logger, settings *artifact.Config) (download2.Verifier, error) {
	allowEmptyPgp, pgp := release.PGP()
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		return localremote.NewVerifier(log, settings, allowEmptyPgp, pgp)
	}

	fsVerifier, err := fs2.NewVerifier(settings, allowEmptyPgp, pgp)
	if err != nil {
		return nil, err
	}

	snapshotVerifier, err := snapshot2.NewVerifier(settings, allowEmptyPgp, pgp, version)
	if err != nil {
		return nil, err
	}

	remoteVerifier, err := http2.NewVerifier(settings, allowEmptyPgp, pgp)
	if err != nil {
		return nil, err
	}

	return composed2.NewVerifier(fsVerifier, snapshotVerifier, remoteVerifier), nil
}
