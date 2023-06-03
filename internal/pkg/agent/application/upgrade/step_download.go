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
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const downloadBackoffInit = 30 * time.Second

//const downloadBackoffInit = 10 * time.Second // FIXME: for testing only

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
	signal := make(chan struct{})
	backExp := backoff.NewExpBackoff(signal, downloadBackoffInit, u.settings.Timeout)

	startTime := time.Now()
	stopRetrying := func(i int) bool {
		// Figure out if we've waited long enough. This ensures we only wait
		// for as long as settings.Timeout across _all_ download attempts
		// in total.
		now := time.Now()
		nextAttemptTime := now.Add(backExp.NextWait())
		waitedLongEnough := nextAttemptTime.Sub(startTime) > settings.Timeout

		if i == 1 || waitedLongEnough {
			// We've unsuccessfully attempted downloading the maximum number of
			// times or we've spent enough time waiting across download attempts.
			// Give up and return the error.
			close(signal)
			u.log.Debugf(
				"attempted downloading %d times over a period of %s.",
				(settings.RetryMaxCount-i)+1,
				now.Sub(startTime).String(),
			)
			return true
		}

		return false
	}

	for i := u.settings.RetryMaxCount; i >= 1; i-- {
		if i < u.settings.RetryMaxCount {
			// Don't wait before the very first attempt
			backExp.Wait()
		}

		downloader, err := downloaderCtor(version, u.log, settings)
		if err != nil {
			if stopRetrying(i) {
				return "", fmt.Errorf("initiating fetcher: %w", err)
			}

			// Retry
			u.log.Warnf("initializing fetcher failed with error [%s]; retrying in %s.", err.Error(), backExp.NextWait().String())
			continue
		}

		path, err := downloader.Download(ctx, agentArtifact, version)
		if err == nil {
			// Download succeeded; we're done here.
			return path, nil
		}

		if stopRetrying(i) {
			return "", fmt.Errorf("downloading: %w", err)
		}

		// Retry
		u.log.Warnf("download attempt failed with error [%s]; retrying in %s.", err.Error(), backExp.NextWait().String())
	}
	close(signal)

	return "", nil
}
