// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"

	"go.elastic.co/apm"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/composed"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/fs"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/http"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/localremote"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/snapshot"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func (u *Upgrader) downloadArtifact(ctx context.Context, version, sourceURI string, skipVerifyOverride bool, pgpBytes ...string) (_ string, err error) {
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

	u.log.Debugw("Downloading upgrade artifact", "version", version,
		"source_uri", settings.SourceURI, "drop_path", settings.DropPath,
		"target_path", settings.TargetDirectory, "install_path", settings.InstallPath)

	if err := os.MkdirAll(paths.Downloads(), 0750); err != nil {
		return "", errors.New(err, fmt.Sprintf("failed to create download directory at %s", paths.Downloads()))
	}

	path, err := u.downloadWithRetries(ctx, newDownloader, version, &settings)
	if err != nil {
		return "", err
	}

	if skipVerifyOverride {
		return path, nil
	}

	verifier, err := newVerifier(version, u.log, &settings)
	if err != nil {
		return "", errors.New(err, "initiating verifier")
	}

	if err := verifier.Verify(agentArtifact, version, pgpBytes...); err != nil {
		return "", errors.New(err, "failed verification of agent binary")
	}

	return path, nil
}

func newDownloader(version string, log *logger.Logger, settings *artifact.Config) (download.Downloader, error) {
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		return localremote.NewDownloader(log, settings)
	}

	// try snapshot repo before official
	snapDownloader, err := snapshot.NewDownloader(log, settings, version)
	if err != nil {
		return nil, err
	}

	httpDownloader, err := http.NewDownloader(log, settings)
	if err != nil {
		return nil, err
	}

	return composed.NewDownloader(fs.NewDownloader(settings), snapDownloader, httpDownloader), nil
}

func newVerifier(version string, log *logger.Logger, settings *artifact.Config) (download.Verifier, error) {
	allowEmptyPgp, pgp := release.PGP()
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		return localremote.NewVerifier(log, settings, allowEmptyPgp, pgp)
	}

	fsVerifier, err := fs.NewVerifier(log, settings, allowEmptyPgp, pgp)
	if err != nil {
		return nil, err
	}

	snapshotVerifier, err := snapshot.NewVerifier(log, settings, allowEmptyPgp, pgp, version)
	if err != nil {
		return nil, err
	}

	remoteVerifier, err := http.NewVerifier(log, settings, allowEmptyPgp, pgp)
	if err != nil {
		return nil, err
	}

	return composed.NewVerifier(fsVerifier, snapshotVerifier, remoteVerifier), nil
}

func (u *Upgrader) downloadWithRetries(
	ctx context.Context,
	downloaderCtor func(string, *logger.Logger, *artifact.Config) (download.Downloader, error),
	version string,
	settings *artifact.Config,
) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, u.settings.Timeout)
	defer cancel()

	expBo := backoff.NewExponentialBackOff()
	expBo.InitialInterval = settings.RetrySleepInitDuration

	boMaxRetries := backoff.WithMaxRetries(expBo, uint64(settings.RetryMaxCount))
	boCtx := backoff.WithContext(boMaxRetries, ctx)

	var path string
	var attempt uint

	opFn := func() error {
		attempt++
		u.log.Debugf("download attempt %d of %d", attempt, settings.RetryMaxCount+1)

		downloader, err := downloaderCtor(version, u.log, settings)
		if err != nil {
			return fmt.Errorf("unable to create fetcher: %w", err)
		}

		path, err = downloader.Download(ctx, agentArtifact, version)
		if err != nil {
			return fmt.Errorf("unable to download package: %w", err)
		}

		// Download successful
		return nil
	}

	opFailureNotificationFn := func(err error, retryAfter time.Duration) {
		u.log.Warnf("%s; retrying (will be retry %d of %d) in %s.", err.Error(), attempt, settings.RetryMaxCount, retryAfter)
	}

	if err := backoff.RetryNotify(opFn, boCtx, opFailureNotificationFn); err != nil {
		return "", err
	}

	return path, nil
}
