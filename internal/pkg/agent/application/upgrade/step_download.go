// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"net/url"
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
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

const (
	defaultUpgradeFallbackPGP     = "https://artifacts.elastic.co/GPG-KEY-elastic-agent"
	fleetUpgradeFallbackPGPFormat = "/api/agents/upgrades/%d.%d.%d/pgp-public-key"
)

type downloaderFactory func(*agtversion.ParsedSemVer, *logger.Logger, *artifact.Config, *details.Details) (download.Downloader, error)

type downloader func(context.Context, downloaderFactory, *agtversion.ParsedSemVer, *artifact.Config, *details.Details) (string, error)

func (u *Upgrader) downloadArtifact(ctx context.Context, parsedVersion *agtversion.ParsedSemVer, sourceURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (_ string, err error) {
	span, ctx := apm.StartSpan(ctx, "downloadArtifact", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	pgpBytes = u.appendFallbackPGP(parsedVersion, pgpBytes)

	// do not update source config
	settings := *u.settings
	var downloaderFunc downloader
	var factory downloaderFactory
	var verifier download.Verifier
	if sourceURI != "" {
		if strings.HasPrefix(sourceURI, "file://") {
			// update the DropPath so the fs.Downloader can download from this
			// path instead of looking into the installed downloads directory
			settings.DropPath = strings.TrimPrefix(sourceURI, "file://")

			// use specific function that doesn't perform retries on download as its
			// local and no retry should be performed
			downloaderFunc = u.downloadOnce

			// set specific downloader, local file just uses the fs.NewDownloader
			// no fallback is allowed because it was requested that this specific source be used
			factory = func(ver *agtversion.ParsedSemVer, l *logger.Logger, config *artifact.Config, d *details.Details) (download.Downloader, error) {
				return fs.NewDownloader(config), nil
			}

			// set specific verifier, local file verifies locally only
			verifier, err = fs.NewVerifier(u.log, &settings, release.PGP())
			if err != nil {
				return "", errors.New(err, "initiating verifier")
			}

			// log that a local upgrade artifact is being used
			u.log.Infow("Using local upgrade artifact", "version", parsedVersion,
				"drop_path", settings.DropPath,
				"target_path", settings.TargetDirectory, "install_path", settings.InstallPath)
		} else {
			settings.SourceURI = sourceURI
		}
	}

	if factory == nil {
		// set the factory to the newDownloader factory
		factory = newDownloader
		u.log.Infow("Downloading upgrade artifact", "version", parsedVersion,
			"source_uri", settings.SourceURI, "drop_path", settings.DropPath,
			"target_path", settings.TargetDirectory, "install_path", settings.InstallPath)
	}
	if downloaderFunc == nil {
		downloaderFunc = u.downloadWithRetries
	}

	if err := os.MkdirAll(paths.Downloads(), 0750); err != nil {
		return "", errors.New(err, fmt.Sprintf("failed to create download directory at %s", paths.Downloads()))
	}

	path, err := downloaderFunc(ctx, factory, parsedVersion, &settings, upgradeDetails)
	if err != nil {
		return "", errors.New(err, "failed download of agent binary")
	}

	if skipVerifyOverride {
		return path, nil
	}

	if verifier == nil {
		verifier, err = newVerifier(parsedVersion, u.log, &settings)
		if err != nil {
			return "", errors.New(err, "initiating verifier")
		}
	}

	if err := verifier.Verify(agentArtifact, *parsedVersion, skipDefaultPgp, pgpBytes...); err != nil {
		return "", errors.New(err, "failed verification of agent binary")
	}
	return path, nil
}

func (u *Upgrader) appendFallbackPGP(targetVersion *agtversion.ParsedSemVer, pgpBytes []string) []string {
	if pgpBytes == nil {
		pgpBytes = make([]string, 0, 1)
	}

	fallbackPGP := download.PgpSourceURIPrefix + defaultUpgradeFallbackPGP
	pgpBytes = append(pgpBytes, fallbackPGP)

	// add a secondary fallback if fleet server is configured
	u.log.Debugf("Considering fleet server uri for pgp check fallback %q", u.fleetServerURI)
	if u.fleetServerURI != "" {
		secondaryPath, err := url.JoinPath(
			u.fleetServerURI,
			fmt.Sprintf(fleetUpgradeFallbackPGPFormat, targetVersion.Major(), targetVersion.Minor(), targetVersion.Patch()),
		)
		if err != nil {
			u.log.Warnf("failed to compose Fleet Server URI: %v", err)
		} else {
			secondaryFallback := download.PgpSourceURIPrefix + secondaryPath
			pgpBytes = append(pgpBytes, secondaryFallback)
		}
	}

	return pgpBytes
}

func newDownloader(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
	if !version.IsSnapshot() {
		return localremote.NewDownloader(log, settings, upgradeDetails)
	}

	// TODO since we know if it's a snapshot or not, shouldn't we add EITHER the snapshot downloader OR the release one ?

	// try snapshot repo before official
	snapDownloader, err := snapshot.NewDownloader(log, settings, version, upgradeDetails)
	if err != nil {
		return nil, err
	}

	httpDownloader, err := http.NewDownloader(log, settings, upgradeDetails)
	if err != nil {
		return nil, err
	}

	return composed.NewDownloader(fs.NewDownloader(settings), snapDownloader, httpDownloader), nil
}

func newVerifier(version *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config) (download.Verifier, error) {
	pgp := release.PGP()

	if !version.IsSnapshot() {
		return localremote.NewVerifier(log, settings, pgp)
	}

	fsVerifier, err := fs.NewVerifier(log, settings, pgp)
	if err != nil {
		return nil, err
	}

	snapshotVerifier, err := snapshot.NewVerifier(log, settings, pgp, version)
	if err != nil {
		return nil, err
	}

	remoteVerifier, err := http.NewVerifier(log, settings, pgp)
	if err != nil {
		return nil, err
	}

	return composed.NewVerifier(log, fsVerifier, snapshotVerifier, remoteVerifier), nil
}

func (u *Upgrader) downloadOnce(
	ctx context.Context,
	factory downloaderFactory,
	version *agtversion.ParsedSemVer,
	settings *artifact.Config,
	upgradeDetails *details.Details,
) (string, error) {
	downloader, err := factory(version, u.log, settings, upgradeDetails)
	if err != nil {
		return "", fmt.Errorf("unable to create fetcher: %w", err)
	}
	// All download artifacts expect a name that includes <major>.<minor.<patch>[-SNAPSHOT] so we have to
	// make sure not to include build metadata we might have in the parsed version (for snapshots we already
	// used that to configure the URL we download the files from)
	path, err := downloader.Download(ctx, agentArtifact, version)
	if err != nil {
		return "", fmt.Errorf("unable to download package: %w", err)
	}

	// Download successful
	return path, nil
}

func (u *Upgrader) downloadWithRetries(
	ctx context.Context,
	factory downloaderFactory,
	version *agtversion.ParsedSemVer,
	settings *artifact.Config,
	upgradeDetails *details.Details,
) (string, error) {
	cancelDeadline := time.Now().Add(settings.Timeout)
	cancelCtx, cancel := context.WithDeadline(ctx, cancelDeadline)
	defer cancel()

	upgradeDetails.SetRetryUntil(&cancelDeadline)

	expBo := backoff.NewExponentialBackOff()
	expBo.InitialInterval = settings.RetrySleepInitDuration
	boCtx := backoff.WithContext(expBo, cancelCtx)

	var path string
	var attempt uint

	opFn := func() error {
		attempt++
		u.log.Infof("download attempt %d", attempt)
		var err error
		path, err = u.downloadOnce(cancelCtx, factory, version, settings, upgradeDetails)
		if err != nil {
			return err
		}
		return nil
	}

	opFailureNotificationFn := func(err error, retryAfter time.Duration) {
		u.log.Warnf("download attempt %d failed: %s; retrying in %s.",
			attempt, err.Error(), retryAfter)
		upgradeDetails.SetRetryableError(err)
	}

	if err := backoff.RetryNotify(opFn, boCtx, opFailureNotificationFn); err != nil {
		return "", err
	}

	// Clear retry details upon success
	upgradeDetails.SetRetryableError(nil)
	upgradeDetails.SetRetryUntil(nil)

	return path, nil
}
