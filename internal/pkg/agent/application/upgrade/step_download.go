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
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

type artifactDownloader struct {
	log            *logger.Logger
	settings       *download.Config
	fleetServerURI string
}

func newArtifactDownloader(settings *download.Config, log *logger.Logger) *artifactDownloader {
	return &artifactDownloader{
		log:      log,
		settings: settings,
	}
}

func (a *artifactDownloader) withFleetServerURI(fleetServerURI string) {
	a.fleetServerURI = fleetServerURI
}

func (a *artifactDownloader) downloadArtifact(ctx context.Context, log *logger.Logger, target download.Artifact, sourceURI string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (_ string, err error) {
	span, ctx := apm.StartSpan(ctx, "downloadArtifact", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	pgpBytes = download.AppendFallbackPGP(a.log, a.fleetServerURI, target.Version, pgpBytes)

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

	switch {
	case sourceURI != "":
	case settings.SourceURI != "":
		sourceURI = settings.SourceURI
	default:
		sourceURI = download.DefaultSourceURI
	}

	if target.Version.IsSnapshot() && sourceURI == download.DefaultSourceURI && target.Version.BuildMetadata() == "" {
		snapshotBuildID, err := latestSnapshotBuildID(ctx, client, target.Version)
		if err != nil {
			return "", fmt.Errorf("retrieving latest snapshot build ID: %w", err)
		}
		target.Version = agtversion.NewParsedSemVer(
			target.Version.Major(),
			target.Version.Minor(),
			target.Version.Patch(),
			target.Version.Prerelease(),
			snapshotBuildID,
		)
	}

	sources := make([]string, 0, 2)
	localUpgradeOnly := download.IsLocal(sourceURI)
	if !localUpgradeOnly {
		sources = append(sources, "file://"+getDropPath(&settings))
	}
	sources = append(sources, sourceURI)

	log.Infow("Downloading upgrade artifact", "version", target.Version,
		"source_uri", sourceURI, "drop_path", settings.DropPath,
		"target_path", settings.TargetDirectory, "install_path", settings.InstallPath, "proxy_uri", settings.Proxy.URL, "proxy_disable", settings.Proxy.Disable)

	if err := os.MkdirAll(paths.Downloads(), 0750); err != nil {
		return "", fmt.Errorf("failed to create download directory at %s: %w", paths.Downloads(), err)
	}

	targetPath := filepath.Join(settings.TargetDirectory, target.FileName)
	errs := make([]error, 0, len(sources))
	for _, sourceURI := range sources {
		resolvedSource, err := Resolve(target, sourceURI)
		if err != nil {
			log.Debugf("[%s] could not resolve source: %v", sourceURI, err)
			errs = append(errs, err)
			continue
		}

		if err = download.Fetch(ctx, log, &settings, upgradeDetails, resolvedSource, targetPath); err != nil {
			e := fmt.Errorf("[%s] could not fetch artifact: %w", sourceURI, err)
			log.Debugf("%v", e)
			errs = append(errs, e)
			continue
		}

		if !skipVerifyOverride {
			if err = download.Fetch(ctx, log, &settings, upgradeDetails, download.AddHashExtension(resolvedSource), download.AddHashExtension(targetPath)); err != nil {
				e := fmt.Errorf("[%s] could not fetch artifact sha512: %w", sourceURI, err)
				log.Debugf("%v", e)
				errs = append(errs, e)
				continue
			}

			if err = download.Verify(ctx, log, &settings, release.PGP(), resolvedSource, targetPath, skipDefaultPgp, pgpBytes...); err != nil {
				e := fmt.Errorf("[%s] verification failed: %w", sourceURI, err)
				log.Debugf("%v", e)
				errs = append(errs, e)
				continue
			}
		}

		return targetPath, nil
	}

	return targetPath, fmt.Errorf("failed download of agent binary: %w", goerrors.Join(errs...))
}

func getDropPath(settings *download.Config) string {
	if settings == nil || settings.DropPath == "" {
		return paths.Downloads()
	}

	stat, err := os.Stat(settings.DropPath)
	if err != nil || !stat.IsDir() {
		return paths.Downloads()
	}

	return settings.DropPath
}

func Resolve(a download.Artifact, sourceURI string) (string, error) {
	if sourceURI == "" {
		sourceURI = download.DefaultSourceURI
	}

	if a.Version.IsSnapshot() && sourceURI == download.DefaultSourceURI {
		// Only artifacts.elastic.co uses .../<build_id>/beats/agent/... for snapshots
		sourceURI = fmt.Sprintf(snapshotURIFormat, a.Version.CoreVersion(), a.Version.BuildMetadata())
	}
	sourceURI = strings.TrimRight(sourceURI, "/")

	if strings.HasPrefix(sourceURI, "/") {
		sourceURI = "file://" + sourceURI
	} else if !download.IsLocal(sourceURI) && !strings.HasPrefix(sourceURI, "http") {
		sourceURI = "https://" + sourceURI
	}

	if download.IsLocal(sourceURI) {
		return sourceURI + "/" + a.FileName, nil
	}

	uri, err := url.JoinPath(sourceURI, "beats", a.Name, a.FileName)
	if err != nil {
		return "", errors.New(err, "invalid upstream source URI")
	}

	return uri, nil
}

const snapshotURIFormat = "https://snapshots.elastic.co/%s-%s/downloads/"

func latestSnapshotBuildID(ctx context.Context, client *http.Client, version *agtversion.ParsedSemVer) (string, error) {
	versionStr := version.CoreVersion()
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

	return snapshotBuildID, nil
}
