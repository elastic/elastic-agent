// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"encoding/json"
	goerrors "errors"
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
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	downloaderrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

const (
	defaultRemoteSourceSubdir = "beats/elastic-agent"
	snapshotURIFormat         = "https://snapshots.elastic.co/%s-%s/downloads/"
)

type artifactDownloader struct {
	log            *logger.Logger
	settings       *artifact.Config
	fleetServerURI string
	getPGPSources  func(log *logger.Logger, fleetServerURI string, targetVersion *agtversion.ParsedSemVer, pgpSources []string) []string
	checkDiskSpace func(context.Context, *artifact.Config, *details.Details, string) (bool, error)
}

func newArtifactDownloader(settings *artifact.Config, log *logger.Logger) *artifactDownloader {
	return &artifactDownloader{
		log:            log,
		settings:       settings,
		getPGPSources:  download.AppendFallbackPGP,
		checkDiskSpace: CheckDiskSpaceAvailable,
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

	pgpBytes = a.getPGPSources(a.log, a.fleetServerURI, target.Version, pgpBytes)

	// do not update source config
	settings := *a.settings

	if sourceURI == "" {
		if settings.SourceURI != "" {
			sourceURI = settings.SourceURI
		} else {
			sourceURI = artifact.DefaultSourceURI
		}
	}

	sources := make([]string, 0, 2)
	if !download.IsLocal(sourceURI) {
		// remote download should check drop path first
		sources = append(sources, "file://"+settings.GetDropPath())
	}
	sources = append(sources, sourceURI)

	fileName := target.FileName()
	if target.Version.IsSnapshot() {
		// Published snapshot artifacts never include the buildID in the file
		// name; it only selects the download URI for the default source. Use
		// the published name for every source so all sources are
		// interchangeable.
		fileName = strings.Replace(fileName, target.Version.String(), target.Version.VersionWithPrerelease(), 1)
	}
	targetPath := filepath.Join(settings.TargetDirectory, fileName)

	if err := os.MkdirAll(settings.TargetDirectory, 0o750); err != nil {
		return "", fmt.Errorf("failed to create target directory %s: %w", settings.TargetDirectory, err)
	}

	var errs []error
	for _, src := range sources {
		resolvedSource, err := Resolve(ctx, &settings, target, src, defaultRemoteSourceSubdir, fileName, upgradeDetails)
		if err != nil {
			e := fmt.Errorf("could not resolve source %s: %w", src, err)
			a.log.Debugf("%v", e)
			errs = append(errs, e)
			continue
		}

		hasDiskSpace, err := a.checkDiskSpace(ctx, &settings, upgradeDetails, resolvedSource)
		if err != nil {
			// Don't fail on err only as CheckDiskSpaceAvailable can err but
			// still have hasDiskSpace=true if we failed to get the exact
			// required size and had to fall back to using an estimate
			e := fmt.Errorf("error checking available disk space for %s: %w", src, err)
			a.log.Debugf("%v", e)
			errs = append(errs, e)
		}
		if !hasDiskSpace {
			if goerrors.Is(err, downloaderrors.ErrFetchUpgradeSizeFailed) {
				// Checking exact required upgrade size failed and an estimated
				// required size was used. We might have enough diskspace for
				// the actual upgrade artifact, so check other sources.
				continue
			}
			break
		}

		if download.IsLocal(resolvedSource) {
			a.log.Infow("Using local upgrade artifact", "version", target.Version,
				"source_uri", resolvedSource, "drop_path", settings.DropPath,
				"target_path", targetPath, "install_path", settings.InstallPath)
		} else {
			a.log.Infow("Downloading upgrade artifact", "version", target.Version,
				"source_uri", resolvedSource, "drop_path", settings.DropPath,
				"target_path", targetPath, "install_path", settings.InstallPath,
				"proxy_uri", settings.Proxy.URL, "proxy_disable", settings.Proxy.Disable)
		}

		if err = download.Fetch(ctx, a.log, &settings, upgradeDetails, resolvedSource, targetPath); err != nil {
			e := fmt.Errorf("could not fetch artifact from %s: %w", src, err)
			a.log.Debugf("%v", e)
			errs = append(errs, e)
			if downloaderrors.IsDiskSpaceError(err) {
				break
			}
			continue
		}

		if !skipVerifyOverride {
			if err = download.Fetch(ctx, a.log, &settings, upgradeDetails, download.AddHashExtension(resolvedSource), download.AddHashExtension(targetPath)); err != nil {
				e := fmt.Errorf("could not fetch artifact sha512 from %s: %w", src, err)
				a.log.Debugf("%v", e)
				errs = append(errs, e)
				if downloaderrors.IsDiskSpaceError(err) {
					break
				}
				continue
			}

			if err = download.Verify(ctx, a.log, &settings, release.PGP(), resolvedSource, targetPath, skipDefaultPgp, pgpBytes...); err != nil {
				e := fmt.Errorf("verification failed for %s: %w", src, err)
				a.log.Debugf("%v", e)
				errs = append(errs, e)
				continue
			}
		}

		return targetPath, nil
	}

	return targetPath, fmt.Errorf("failed to obtain agent artifact: %w", goerrors.Join(errs...))
}

// Resolve computes the fully resolved download URI for an artifact.
func Resolve(ctx context.Context, config *artifact.Config, target artifact.Artifact, sourceURI, sourceSubdir, fileName string, upgradeDetails *details.Details) (string, error) {
	if target.Version.IsSnapshot() && sourceURI == artifact.DefaultSourceURI {
		// Only use the special snapshot URI format when the default source URI is used
		buildID := target.Version.BuildMetadata()
		if buildID == "" {
			var err error
			buildID, err = latestSnapshotBuildID(ctx, config, target.Version, upgradeDetails)
			if err != nil {
				return "", fmt.Errorf("retrieving latest snapshot build ID: %w", err)
			}
		}

		sourceURI = fmt.Sprintf(snapshotURIFormat, target.Version.CoreVersion(), buildID)
	}

	if strings.HasPrefix(sourceURI, "/") || strings.HasPrefix(sourceURI, "file://") {
		sourcePath := filepath.Join(strings.TrimPrefix(sourceURI, "file://"), fileName)
		return "file://" + filepath.ToSlash(sourcePath), nil
	}

	if !strings.HasPrefix(sourceURI, "http://") && !strings.HasPrefix(sourceURI, "https://") {
		sourceURI = "https://" + sourceURI
	}

	uri, err := url.JoinPath(sourceURI, sourceSubdir, fileName)
	if err != nil {
		return "", errors.New(err, "invalid download source URI")
	}

	return uri, nil
}

func latestSnapshotBuildID(ctx context.Context, config *artifact.Config, version *agtversion.ParsedSemVer, upgradeDetails *details.Details) (string, error) {
	cancelDeadline := time.Now().Add(config.Timeout)
	cancelCtx, cancel := context.WithDeadline(ctx, cancelDeadline)
	defer cancel()

	upgradeDetails.SetRetryUntil(&cancelDeadline)

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
		upgradeDetails.SetRetryableError(err)
	}

	if err := backoff.RetryNotify(opFn, boCtx, opFailureNotificationFn); err != nil {
		return "", err
	}

	// Clear retry details upon success
	upgradeDetails.SetRetryableError(nil)
	upgradeDetails.SetRetryUntil(nil)

	return snapshotBuildID, nil
}
