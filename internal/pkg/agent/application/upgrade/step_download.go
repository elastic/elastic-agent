// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"

	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/composed"
	downloadErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
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

// abstraction for testability for newVerifier
type verifierFactory func(*agtversion.ParsedSemVer, *logger.Logger, *artifact.Config) (download.Verifier, error)

type artifactDownloader struct {
	log            *logger.Logger
	settings       *artifact.Config
	fleetServerURI string
	newVerifier    verifierFactory
}

func newArtifactDownloader(settings *artifact.Config, log *logger.Logger) *artifactDownloader {
	return &artifactDownloader{
		log:         log,
		settings:    settings,
		newVerifier: newVerifier,
	}
}

func (a *artifactDownloader) withFleetServerURI(fleetServerURI string) {
	a.fleetServerURI = fleetServerURI
}

func (a *artifactDownloader) downloadArtifact(ctx context.Context, parsedVersion *agtversion.ParsedSemVer, sourceURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (_ string, err error) {
	span, ctx := apm.StartSpan(ctx, "downloadArtifact", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	pgpBytes = a.appendFallbackPGP(parsedVersion, pgpBytes)

	// do not update source config
	settings := *a.settings
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
			downloaderFunc = a.downloadOnce

			// set specific downloader, local file just uses the fs.NewDownloader
			// no fallback is allowed because it was requested that this specific source be used
			factory = func(ver *agtversion.ParsedSemVer, l *logger.Logger, config *artifact.Config, d *details.Details) (download.Downloader, error) {
				return fs.NewDownloader(config), nil
			}

			// set specific verifier, local file verifies locally only
			verifier, err = fs.NewVerifier(a.log, &settings, release.PGP())
			if err != nil {
				return "", errors.New(err, "initiating verifier")
			}

			// log that a local upgrade artifact is being used
			a.log.Infow("Using local upgrade artifact", "version", parsedVersion,
				"drop_path", settings.DropPath,
				"target_path", settings.TargetDirectory, "install_path", settings.InstallPath)
		} else {
			settings.SourceURI = sourceURI
		}
	}

	if factory == nil {
		// set the factory to the newDownloader factory
		factory = newDownloader
		a.log.Infow("Downloading upgrade artifact", "version", parsedVersion,
			"source_uri", settings.SourceURI, "drop_path", settings.DropPath,
			"target_path", settings.TargetDirectory, "install_path", settings.InstallPath)
	}
	if downloaderFunc == nil {
		downloaderFunc = a.downloadWithRetries
	}

	if err := os.MkdirAll(paths.Downloads(), 0750); err != nil {
		return "", fmt.Errorf("failed to create download directory at %s: %w", paths.Downloads(), err)
	}

	path, err := downloaderFunc(ctx, factory, parsedVersion, &settings, upgradeDetails)
	if err != nil {
		return "", fmt.Errorf("failed download of agent binary: %w", err)
	}

	// If there are errors in the following steps, we return the path so that we
	// can cleanup the downloaded files.
	if skipVerifyOverride {
		return path, nil
	}

	if verifier == nil {
		verifier, err = a.newVerifier(parsedVersion, a.log, &settings)
		if err != nil {
			return path, errors.New(err, "initiating verifier")
		}
	}

	if err := verifier.Verify(ctx, agentArtifact, *parsedVersion, skipDefaultPgp, pgpBytes...); err != nil {
		return path, errors.New(err, "failed verification of agent binary")
	}
	return path, nil
}

func (a *artifactDownloader) appendFallbackPGP(targetVersion *agtversion.ParsedSemVer, pgpBytes []string) []string {
	if pgpBytes == nil {
		pgpBytes = make([]string, 0, 1)
	}

	fallbackPGP := download.PgpSourceURIPrefix + defaultUpgradeFallbackPGP
	pgpBytes = append(pgpBytes, fallbackPGP)

	// add a secondary fallback if fleet server is configured
	a.log.Debugf("Considering fleet server uri for pgp check fallback %q", a.fleetServerURI)
	if a.fleetServerURI != "" {
		secondaryPath, err := url.JoinPath(
			a.fleetServerURI,
			fmt.Sprintf(fleetUpgradeFallbackPGPFormat, targetVersion.Major(), targetVersion.Minor(), targetVersion.Patch()),
		)
		if err != nil {
			a.log.Warnf("failed to compose Fleet Server URI: %v", err)
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

func (a *artifactDownloader) downloadOnce(
	ctx context.Context,
	factory downloaderFactory,
	version *agtversion.ParsedSemVer,
	settings *artifact.Config,
	upgradeDetails *details.Details,
) (string, error) {
	downloader, err := factory(version, a.log, settings, upgradeDetails)
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

func (a *artifactDownloader) downloadWithRetries(
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
		a.log.Infof("download attempt %d", attempt)
		var err error
		path, err = a.downloadOnce(cancelCtx, factory, version, settings, upgradeDetails)
		if err != nil {
			if downloadErrors.IsDiskSpaceError(err) {
				a.log.Infof("insufficient disk space error detected, stopping retries")
				return backoff.Permanent(err)
			}
			return err
		}
		return nil
	}

	opFailureNotificationFn := func(err error, retryAfter time.Duration) {
		a.log.Warnf("download attempt %d failed: %s; retrying in %s.",
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
