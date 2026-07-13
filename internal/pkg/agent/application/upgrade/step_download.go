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
	"path/filepath"
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
	defaultRemoteSourceSubdir     = "beats/elastic-agent"
	defaultUpgradeFallbackPGP     = "https://artifacts.elastic.co/GPG-KEY-elastic-agent"
	fleetUpgradeFallbackPGPFormat = "/api/agents/upgrades/%d.%d.%d/pgp-public-key"
	snapshotURIFormat             = "https://snapshots.elastic.co/%s-%s/downloads/"
)

type downloaderFactory func(*logger.Logger, *artifact.Config, *details.Details) (download.Downloader, error)

type downloader func(context.Context, downloaderFactory, artifact.Artifact, string, string, string, *artifact.Config, *details.Details) (string, error)

// abstraction for testability for newVerifier
type verifierFactory func(*logger.Logger, *artifact.Config) (download.Verifier, error)

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

func (a *artifactDownloader) downloadArtifact(ctx context.Context, target artifact.Artifact, sourceURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (_ string, err error) {
	span, ctx := apm.StartSpan(ctx, "downloadArtifact", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	pgpBytes = a.appendFallbackPGP(target.Version, pgpBytes)

	// do not update source config
	settings := *a.settings

	fileName, sourceDir, targetDir, err := Resolve(ctx, &settings, target, sourceURI, defaultRemoteSourceSubdir, upgradeDetails)
	if err != nil {
		return "", fmt.Errorf("failed to resolve agent download url: %w", err)
	}

	isLocal := strings.HasPrefix(sourceDir, "file://")
	targetPath := filepath.Join(targetDir, fileName)

	var downloaderFunc downloader
	var factory downloaderFactory
	var verifier download.Verifier
	if isLocal {
		// use specific function that doesn't perform retries on download as its
		// local and no retry should be performed
		downloaderFunc = a.downloadOnce

		// set specific downloader, local file just uses the fs.NewDownloader
		// no fallback is allowed because it was requested that this specific source be used
		factory = func(l *logger.Logger, config *artifact.Config, d *details.Details) (download.Downloader, error) {
			return fs.NewDownloader(config), nil
		}

		// set specific verifier, local file verifies locally only
		verifier, err = fs.NewVerifier(a.log, &settings, release.PGP())
		if err != nil {
			return "", errors.New(err, "initiating verifier")
		}

		// log that a local upgrade artifact is being used
		a.log.Infow("Using local upgrade artifact", "version", target.Version,
			"source_uri", strings.TrimRight(sourceDir, "/")+"/"+fileName,
			"target_path", targetPath, "install_path", settings.InstallPath)
	} else {
		downloaderFunc = a.downloadWithRetries
		factory = newDownloader
		a.log.Infow("Downloading upgrade artifact", "version", target.Version,
			"source_uri", sourceDir, "drop_path", settings.DropPath,
			"target_path", targetPath, "install_path", settings.InstallPath, "proxy_uri", settings.Proxy.URL, "proxy_disable", settings.Proxy.Disable)
	}

	if err := os.MkdirAll(paths.Downloads(), 0750); err != nil {
		return "", fmt.Errorf("failed to create download directory at %s: %w", paths.Downloads(), err)
	}

	path, err := downloaderFunc(ctx, factory, target, fileName, sourceDir, targetDir, &settings, upgradeDetails)
	if err != nil {
		return "", fmt.Errorf("failed download of agent binary: %w", err)
	}

	// If there are errors in the following steps, we return the path so that we
	// can cleanup the downloaded files.
	if skipVerifyOverride {
		return path, nil
	}

	if verifier == nil {
		verifier, err = a.newVerifier(a.log, &settings)
		if err != nil {
			return path, errors.New(err, "initiating verifier")
		}
	}

	if err := verifier.Verify(ctx, target, fileName, sourceDir, targetDir, skipDefaultPgp, pgpBytes...); err != nil {
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

func newDownloader(log *logger.Logger, settings *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
	return localremote.NewDownloader(log, settings, upgradeDetails)
}

func newVerifier(log *logger.Logger, settings *artifact.Config) (download.Verifier, error) {
	return localremote.NewVerifier(log, settings, release.PGP())
}

func (a *artifactDownloader) downloadOnce(
	ctx context.Context,
	factory downloaderFactory,
	target artifact.Artifact,
	filename string,
	sourceDir string,
	targetDir string,
	settings *artifact.Config,
	upgradeDetails *details.Details,
) (string, error) {
	downloader, err := factory(a.log, settings, upgradeDetails)
	if err != nil {
		return "", fmt.Errorf("unable to create fetcher: %w", err)
	}
	path, err := downloader.Download(ctx, target, filename, sourceDir, targetDir)
	if err != nil {
		return "", fmt.Errorf("unable to download package: %w", err)
	}

	// Download successful
	return path, nil
}

func (a *artifactDownloader) downloadWithRetries(
	ctx context.Context,
	factory downloaderFactory,
	target artifact.Artifact,
	filename string,
	sourceDir string,
	targetDir string,
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
		path, err = a.downloadOnce(cancelCtx, factory, target, filename, sourceDir, targetDir, settings, upgradeDetails)
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

// Resolve computes the artifact filename, source directory, and target directory for the target artifact.
func Resolve(ctx context.Context, config *artifact.Config, target artifact.Artifact, sourceURI, sourceSubdir string, upgradeDetails *details.Details) (string, string, string, error) {
	if sourceURI == "" {
		if config.SourceURI != "" {
			sourceURI = config.SourceURI
		} else {
			sourceURI = artifact.DefaultSourceURI
		}
	}

	if target.Version.IsSnapshot() && sourceURI == artifact.DefaultSourceURI {
		// Only use the special snapshot URI format when the default source URI is used
		buildID := target.Version.BuildMetadata()
		if buildID == "" {
			var err error
			buildID, err = latestSnapshotBuildID(ctx, config, target.Version, upgradeDetails)
			if err != nil {
				return "", "", "", fmt.Errorf("retrieving latest snapshot build ID: %w", err)
			}
		}

		sourceURI = fmt.Sprintf(snapshotURIFormat, target.Version.CoreVersion(), buildID)
	}

	if strings.HasPrefix(sourceURI, "/") {
		sourceURI = "file://" + sourceURI
	}

	if !strings.HasPrefix(sourceURI, "file://") {
		if !strings.HasPrefix(sourceURI, "http://") && !strings.HasPrefix(sourceURI, "https://") {
			sourceURI = "https://" + sourceURI
		}
		url, err := url.Parse(sourceURI)
		if err != nil {
			return "", "", "", errors.New(err, "invalid download source URI")
		}
		sourceURI = url.String()
	}

	fileName := target.FileName()
	if strings.HasPrefix(sourceURI, "file://") {
		return fileName, sourceURI, config.TargetDirectory, nil
	}

	if target.Version.IsSnapshot() {
		// Strip the buildID from remote snapshot filename
		fileName = strings.Replace(fileName, target.Version.String(), target.Version.VersionWithPrerelease(), 1)
	}

	sourceDir, err := url.JoinPath(sourceURI, sourceSubdir)
	if err != nil {
		return "", "", "", errors.New(err, "invalid download source URI")
	}

	return fileName, sourceDir, config.TargetDirectory, nil
}

func latestSnapshotBuildID(ctx context.Context, config *artifact.Config, version *agtversion.ParsedSemVer, upgradeDetails *details.Details) (string, error) {
	cancelDeadline := time.Now().Add(config.Timeout)
	cancelCtx, cancel := context.WithDeadline(ctx, cancelDeadline)
	defer cancel()

	if upgradeDetails != nil {
		upgradeDetails.SetRetryUntil(&cancelDeadline)
	}

	expBo := backoff.NewExponentialBackOff()
	expBo.InitialInterval = config.RetrySleepInitDuration
	boCtx := backoff.WithContext(expBo, cancelCtx)

	client, err := config.Client(
		httpcommon.WithAPMHTTPInstrumentation(),
		httpcommon.WithModRoundtripper(func(rt http.RoundTripper) http.RoundTripper {
			return download.WithHeaders(rt, download.Headers)
		}),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP client for resolving snapshot download url: %w", err)
	}

	var snapshotBuildID string
	versionStr := version.CoreVersion()
	latestSnapshotURI := fmt.Sprintf("https://snapshots.elastic.co/latest/%s-SNAPSHOT.json", versionStr)

	opFn := func() error {
		req, err := http.NewRequestWithContext(cancelCtx, http.MethodGet, latestSnapshotURI, nil)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("failed to create request to the snapshot API: %w", err))
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusNotFound:
			return backoff.Permanent(fmt.Errorf("snapshot for version %q not found", versionStr))
		case http.StatusOK:
			var info struct {
				BuildID string `json:"build_id"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
				return backoff.Permanent(err)
			}
			parts := strings.Split(info.BuildID, "-")
			if len(parts) != 2 {
				return backoff.Permanent(fmt.Errorf("wrong format for a build ID: %s", info.BuildID))
			}
			snapshotBuildID = parts[1]
			return nil
		default:
			return fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, latestSnapshotURI)
		}
	}

	opFailureNotificationFn := func(err error, _ time.Duration) {
		if upgradeDetails != nil {
			upgradeDetails.SetRetryableError(err)
		}
	}

	if err := backoff.RetryNotify(opFn, boCtx, opFailureNotificationFn); err != nil {
		return "", err
	}

	// Clear retry details upon success
	if upgradeDetails != nil {
		upgradeDetails.SetRetryableError(nil)
		upgradeDetails.SetRetryUntil(nil)
	}

	return snapshotBuildID, nil
}
