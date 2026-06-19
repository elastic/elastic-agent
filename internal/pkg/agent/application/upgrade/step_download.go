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
	defaultUpgradeFallbackPGP     = "https://artifacts.elastic.co/GPG-KEY-elastic-agent"
	fleetUpgradeFallbackPGPFormat = "/api/agents/upgrades/%d.%d.%d/pgp-public-key"
)

type downloaderFactory func(*logger.Logger, *artifact.Config, *details.Details) (download.Downloader, error)

type downloader func(context.Context, downloaderFactory, artifact.Artifact, *artifact.Config, string, string, *details.Details) error

// abstraction for testability for the verifier constructor
type verifierFactory func(*logger.Logger, *artifact.Config, []byte) (download.Verifier, error)

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
		newVerifier: localremote.NewVerifier,
	}
}

func (a *artifactDownloader) withFleetServerURI(fleetServerURI string) {
	a.fleetServerURI = fleetServerURI
}

func (a *artifactDownloader) downloadArtifact(ctx context.Context, target artifact.Artifact, targetSource string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (_ string, err error) {
	span, ctx := apm.StartSpan(ctx, "downloadArtifact", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	pgpBytes = a.appendFallbackPGP(target.Version, pgpBytes)

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

	isLocal, src, err := Resolve(ctx, client, target, targetSource)
	if err != nil {
		return "", fmt.Errorf("failed to resolve agent binary download url: %w", err)
	}

	var downloaderFunc downloader
	var factory downloaderFactory
	if isLocal {
		// use specific function that doesn't perform retries on download as its
		// local and no retry should be performed
		downloaderFunc = a.downloadOnce
		factory = func(l *logger.Logger, config *artifact.Config, d *details.Details) (download.Downloader, error) {
			return fs.NewDownloader(config), nil
		}
		a.log.Infow("Using local upgrade artifact", "version", target.Version,
			"drop_path", settings.DropPath,
			"target_path", settings.TargetDirectory, "install_path", settings.InstallPath)
	} else {
		downloaderFunc = a.downloadWithRetries
		factory = localremote.NewDownloader
		a.log.Infow("Downloading upgrade artifact", "version", target.Version,
			"source_uri", targetSource, "drop_path", settings.DropPath,
			"target_path", settings.TargetDirectory, "install_path", settings.InstallPath, "proxy_uri", settings.Proxy.URL, "proxy_disable", settings.Proxy.Disable)
	}

	if err := os.MkdirAll(paths.Downloads(), 0750); err != nil {
		return "", fmt.Errorf("failed to create download directory at %s: %w", paths.Downloads(), err)
	}

	path := filepath.Join(settings.TargetDirectory, target.FileName)
	if err := downloaderFunc(ctx, factory, target, &settings, src, path, upgradeDetails); err != nil {
		return "", fmt.Errorf("failed download of agent binary: %w", err)
	}

	// If there are errors in the following steps, we return the path so that we
	// can cleanup the downloaded files.
	if skipVerifyOverride {
		return path, nil
	}

	var verifier download.Verifier
	verifier, err = a.newVerifier(a.log, &settings, release.PGP())
	if err != nil {
		return path, errors.New(err, "initiating verifier")
	}

	if err := verifier.Verify(ctx, target, src, path, skipDefaultPgp, pgpBytes...); err != nil {
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

func (a *artifactDownloader) downloadOnce(
	ctx context.Context,
	factory downloaderFactory,
	target artifact.Artifact,
	settings *artifact.Config,
	src string,
	dst string,
	upgradeDetails *details.Details,
) error {
	downloader, err := factory(a.log, settings, upgradeDetails)
	if err != nil {
		return fmt.Errorf("unable to create fetcher: %w", err)
	}
	if err := downloader.Download(ctx, target, src, dst); err != nil {
		return fmt.Errorf("unable to download package: %w", err)
	}
	return nil
}

func (a *artifactDownloader) downloadWithRetries(
	ctx context.Context,
	factory downloaderFactory,
	target artifact.Artifact,
	settings *artifact.Config,
	src string,
	dst string,
	upgradeDetails *details.Details,
) error {
	cancelDeadline := time.Now().Add(settings.Timeout)
	cancelCtx, cancel := context.WithDeadline(ctx, cancelDeadline)
	defer cancel()

	upgradeDetails.SetRetryUntil(&cancelDeadline)

	expBo := backoff.NewExponentialBackOff()
	expBo.InitialInterval = settings.RetrySleepInitDuration
	boCtx := backoff.WithContext(expBo, cancelCtx)

	var attempt uint

	opFn := func() error {
		attempt++
		a.log.Infof("download attempt %d", attempt)
		if err := a.downloadOnce(cancelCtx, factory, target, settings, src, dst, upgradeDetails); err != nil {
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
		return err
	}

	// Clear retry details upon success
	upgradeDetails.SetRetryableError(nil)
	upgradeDetails.SetRetryUntil(nil)

	return nil
}

// Resolve resolves sourceURI for the given artifact into a full local path or remote URL.
// Returns isLocal=true and the local file path when sourceURI is a file:// URI,
// or isLocal=false and the full remote URL otherwise. The client is used to look
// up the latest snapshot build when resolving a snapshot version.
func Resolve(ctx context.Context, client *http.Client, a artifact.Artifact, sourceURI string) (bool, string, error) {
	if path, ok := strings.CutPrefix(sourceURI, "file://"); ok {
		return true, strings.TrimRight(path, "/") + "/" + a.FileName, nil
	}
	if sourceURI == "" {
		sourceURI = artifact.DefaultSourceURI
	}
	base := sourceURI
	if a.Version.IsSnapshot() {
		resolved, err := resolveSnapshotSourceURI(ctx, client, a, sourceURI)
		if err != nil {
			return false, "", fmt.Errorf("resolving snapshot source URI: %w", err)
		}
		base = resolved
	}
	if !strings.HasPrefix(base, "http") && !strings.HasPrefix(base, "file") && !strings.HasPrefix(base, "/") {
		base = "https://" + base
	}
	return false, strings.TrimRight(base, "/") + "/beats/elastic-agent/" + a.FileName, nil
}

const snapshotURIFormat = "https://snapshots.elastic.co/%s-%s/downloads/"

func resolveSnapshotSourceURI(ctx context.Context, client *http.Client, a artifact.Artifact, sourceURI string) (string, error) {
	if sourceURI != artifact.DefaultSourceURI {
		return sourceURI, nil
	}

	if buildID := a.Version.BuildMetadata(); buildID != "" {
		return fmt.Sprintf(snapshotURIFormat, a.Version.CoreVersion(), buildID), nil
	}

	versionStr := a.Version.CoreVersion()
	latestSnapshotURI := fmt.Sprintf("https://snapshots.elastic.co/latest/%s-SNAPSHOT.json", versionStr)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var snapshotBuildID string
	op := func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestSnapshotURI, nil)
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

	if err := backoff.Retry(op, backoff.WithContext(backoff.NewExponentialBackOff(), ctx)); err != nil {
		return "", err
	}

	return fmt.Sprintf(snapshotURIFormat, versionStr, snapshotBuildID), nil
}
