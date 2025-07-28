// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	gohttp "net/http"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/http"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

const snapshotURIFormat = "https://snapshots.elastic.co/%s-%s/downloads/"

type Downloader struct {
	downloader      download.Downloader
	versionOverride *agtversion.ParsedSemVer
	client          *gohttp.Client
}

// NewDownloader creates a downloader which first checks local directory
// and then fallbacks to remote if configured.
// We need to pass the versionOverride separately from the config as
// artifact.Config struct is part of agent configuration and a version
// override makes no sense there
func NewDownloader(log *logger.Logger, config *artifact.Config, versionOverride *agtversion.ParsedSemVer, upgradeDetails *details.Details) (download.Downloader, error) {
	client, err := config.HTTPTransportSettings.Client(
		httpcommon.WithAPMHTTPInstrumentation(),
		httpcommon.WithKeepaliveSettings{Disable: false, IdleConnTimeout: 30 * time.Second},
	)
	if err != nil {
		return nil, err
	}

	return NewDownloaderWithClient(log, config, versionOverride, client, upgradeDetails)
}

func NewDownloaderWithClient(log *logger.Logger, config *artifact.Config, versionOverride *agtversion.ParsedSemVer, client *gohttp.Client, upgradeDetails *details.Details) (download.Downloader, error) {
	// TODO: decide an appropriate timeout for this
	cfg, err := snapshotConfig(context.TODO(), client, config, versionOverride)
	if err != nil {
		return nil, fmt.Errorf("error creating snapshot config: %w", err)
	}

	httpDownloader := http.NewDownloaderWithClient(log, cfg, *client, upgradeDetails)

	return &Downloader{
		downloader:      httpDownloader,
		versionOverride: versionOverride,
		client:          client,
	}, nil
}

func (e *Downloader) Reload(c *artifact.Config) error {
	reloader, ok := e.downloader.(artifact.ConfigReloader)
	if !ok {
		return nil
	}

	// TODO: decide an appropriate timeout for this
	cfg, err := snapshotConfig(context.TODO(), e.client, c, e.versionOverride)
	if err != nil {
		return fmt.Errorf("snapshot.downloader: failed to generate snapshot config: %w", err)
	}

	return reloader.Reload(cfg)
}

// Download fetches the package from configured source.
// Returns absolute path to downloaded package and an error.
func (e *Downloader) Download(ctx context.Context, a artifact.Artifact, version *agtversion.ParsedSemVer) (string, error) {
	// remove build metadata to match filename of the package for the specific snapshot build
	strippedVersion := agtversion.NewParsedSemVer(version.Major(), version.Minor(), version.Patch(), version.Prerelease(), "")
	return e.downloader.Download(ctx, a, strippedVersion)
}

func snapshotConfig(ctx context.Context, client *gohttp.Client, config *artifact.Config, versionOverride *agtversion.ParsedSemVer) (*artifact.Config, error) {
	snapshotURI, err := snapshotURI(ctx, client, versionOverride, config)
	if err != nil {
		return nil, fmt.Errorf("failed to detect remote snapshot repo, proceeding with configured: %w", err)
	}

	return &artifact.Config{
		OperatingSystem: config.OperatingSystem,
		Architecture:    config.Architecture,
		SourceURI:       snapshotURI,
		TargetDirectory: config.TargetDirectory,
		InstallPath:     config.InstallPath,
		DropPath:        config.DropPath,

		HTTPTransportSettings: config.HTTPTransportSettings,
	}, nil
}

func snapshotURI(ctx context.Context, client *gohttp.Client, versionOverride *agtversion.ParsedSemVer, config *artifact.Config) (string, error) {
	// Respect a non-default source URI even if the version is a snapshot.
	if config.SourceURI != artifact.DefaultSourceURI {
		return config.SourceURI, nil
	}

	// snapshot downloader is used also by the 'localremote' impl in case of agent currently running off a snapshot build:
	// the 'localremote' downloader does not pass a specific version, implying that we should update to the latest snapshot
	// build of the same <major>.<minor>.<patch>-SNAPSHOT version
	version := release.Version()
	if versionOverride != nil {
		if versionOverride.BuildMetadata() != "" {
			// we know exactly which snapshot build we want to target
			return fmt.Sprintf(snapshotURIFormat, versionOverride.CoreVersion(), versionOverride.BuildMetadata()), nil
		}

		version = versionOverride.CoreVersion()
	}

	// otherwise, if we don't know the exact build and we're trying to find the latest snapshot build
	buildID, err := findLatestSnapshot(ctx, client, version)
	if err != nil {
		return "", fmt.Errorf("failed to find snapshot information for version %q: %w", version, err)
	}

	return fmt.Sprintf(snapshotURIFormat, version, buildID), nil
}

func findLatestSnapshot(ctx context.Context, client *gohttp.Client, version string) (buildID string, err error) {
	latestSnapshotURI := fmt.Sprintf("https://snapshots.elastic.co/latest/%s-SNAPSHOT.json", version)
	request, err := gohttp.NewRequestWithContext(ctx, gohttp.MethodGet, latestSnapshotURI, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request to the snapshot API: %w", err)
	}

	resp, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case gohttp.StatusNotFound:
		return "", fmt.Errorf("snapshot for version %q not found", version)

	case gohttp.StatusOK:
		var info struct {
			BuildID string `json:"build_id"`
		}

		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&info); err != nil {
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
