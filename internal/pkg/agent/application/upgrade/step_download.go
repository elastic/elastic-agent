// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"

	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	downloadErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/fs"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/localremote"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
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

	client, err := settings.HTTPTransportSettings.Client(
		httpcommon.WithAPMHTTPInstrumentation(),
		httpcommon.WithModRoundtripper(func(rt http.RoundTripper) http.RoundTripper {
			return download.WithHeaders(rt, download.Headers)
		}),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP client for resolving agent binary download url: %w", err)
	}

	if sourceURI == "" {
		sourceURI = settings.SourceURI
	}

	isLocal, resolvedSourceURI, err := Resolve(ctx, client, parsedVersion, sourceURI)
	if err != nil {
		return "", fmt.Errorf("failed to resolve agent binary download url: %w", err)
	}

	var downloaderFunc downloader
	var factory downloaderFactory
	var verifier download.Verifier
	if isLocal {
		// update the DropPath so the fs.Downloader can download from this
		// path instead of looking into the installed downloads directory
		settings.DropPath = strings.TrimPrefix(resolvedSourceURI, "file://")

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
		settings.SourceURI = resolvedSourceURI
		downloaderFunc = a.downloadWithRetries
		factory = newDownloader
		a.log.Infow("Downloading upgrade artifact", "version", parsedVersion,
			"source_uri", settings.SourceURI, "drop_path", settings.DropPath,
			"target_path", settings.TargetDirectory, "install_path", settings.InstallPath, "proxy_uri", settings.Proxy.URL, "proxy_disable", settings.Proxy.Disable)
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

func newDownloader(_ *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
	return localremote.NewDownloader(log, settings, upgradeDetails)
}

func newVerifier(_ *agtversion.ParsedSemVer, log *logger.Logger, settings *artifact.Config) (download.Verifier, error) {
	return localremote.NewVerifier(log, settings, release.PGP())
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

func Resolve(ctx context.Context, client *http.Client, version *agtversion.ParsedSemVer, sourceURI string) (bool, string, error) {
	if sourceURI == "" {
		sourceURI = artifact.DefaultSourceURI
	}

	if strings.HasPrefix(sourceURI, "file://") {
		return true, sourceURI, nil
	}

	// Only snapshots pulled from the default snapshot repository need a build ID
	// lookup; a non-default source URI is used unchanged.
	if version.IsSnapshot() && sourceURI == artifact.DefaultSourceURI {
		if buildID := version.BuildMetadata(); buildID != "" {
			// we know exactly which snapshot build we want to target
			return false, fmt.Sprintf(snapshotURIFormat, version.CoreVersion(), buildID), nil
		}

		buildID, err := findLatestSnapshot(ctx, client, version.CoreVersion())
		if err != nil {
			return false, "", fmt.Errorf("failed to find snapshot information for version %q: %w", version.CoreVersion(), err)
		}
		return false, fmt.Sprintf(snapshotURIFormat, version.CoreVersion(), buildID), nil
	}

	return false, sourceURI, nil
}

const snapshotURIFormat = "https://snapshots.elastic.co/%s-%s/downloads/"

func findLatestSnapshot(ctx context.Context, client *http.Client, version string) (string, error) {
	latestSnapshotURI := fmt.Sprintf("https://snapshots.elastic.co/latest/%s-SNAPSHOT.json", version)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, latestSnapshotURI, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request to the snapshot API: %w", err)
	}

	resp, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return "", fmt.Errorf("snapshot for version %q not found", version)

	case http.StatusOK:
		var info struct {
			BuildID string `json:"build_id"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			return "", err
		}

		parts := strings.Split(info.BuildID, "-")
		if len(parts) != 2 {
			return "", fmt.Errorf("wrong format for a build ID: %s", info.BuildID)
		}

		return parts[1], nil

	default:
		return "", fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, latestSnapshotURI)
	}
}
