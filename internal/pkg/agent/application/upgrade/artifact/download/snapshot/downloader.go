// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/http"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

const snapshotURIFormat = "https://snapshots.elastic.co/%s-%s/downloads/"

type Downloader struct {
	downloader      download.Downloader
	versionOverride *agtversion.ParsedSemVer
}

// NewDownloader creates a downloader which first checks local directory
// and then fallbacks to remote if configured.
// We need to pass the versionOverride separately from the config as
// artifact.Config struct is part of agent configuration and a version
// override makes no sense there
func NewDownloader(log *logger.Logger, config *artifact.Config, versionOverride *agtversion.ParsedSemVer) (download.Downloader, error) {
	cfg, err := snapshotConfig(config, versionOverride)
	if err != nil {
		return nil, fmt.Errorf("error creating snapshot config: %w", err)
	}

	httpDownloader, err := http.NewDownloader(log, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot downloader: %w", err)
	}

	return &Downloader{
		downloader:      httpDownloader,
		versionOverride: versionOverride,
	}, nil
}

func (e *Downloader) Reload(c *artifact.Config) error {
	reloader, ok := e.downloader.(artifact.ConfigReloader)
	if !ok {
		return nil
	}

	cfg, err := snapshotConfig(c, e.versionOverride)
	if err != nil {
		return fmt.Errorf("snapshot.downloader: failed to generate snapshot config: %w", err)
	}

	return reloader.Reload(cfg)
}

// Download fetches the package from configured source.
// Returns absolute path to downloaded package and an error.
func (e *Downloader) Download(ctx context.Context, a artifact.Artifact, version string) (string, error) {
	return e.downloader.Download(ctx, a, version)
}

func snapshotConfig(config *artifact.Config, versionOverride *agtversion.ParsedSemVer) (*artifact.Config, error) {
	snapshotURI, err := snapshotURI(versionOverride, config)
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

func snapshotURI(versionOverride *agtversion.ParsedSemVer, config *artifact.Config) (string, error) {
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

	// we go through the artifact API to find the location of the latest snapshot build for the specified version
	client, err := config.HTTPTransportSettings.Client(httpcommon.WithAPMHTTPInstrumentation())
	if err != nil {
		return "", err
	}

	artifactsURI := fmt.Sprintf("https://artifacts-api.elastic.co/v1/search/%s-SNAPSHOT/elastic-agent", version)
	resp, err := client.Get(artifactsURI)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body := struct {
		Packages map[string]interface{} `json:"packages"`
	}{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&body); err != nil {
		return "", err
	}

	if len(body.Packages) == 0 {
		return "", fmt.Errorf("no packages found in snapshot repo")
	}

	for k, pkg := range body.Packages {
		pkgMap, ok := pkg.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("content of '%s' is not a map", k)
		}

		uriVal, found := pkgMap["url"]
		if !found {
			return "", fmt.Errorf("item '%s' does not contain url", k)
		}

		uri, ok := uriVal.(string)
		if !ok {
			return "", fmt.Errorf("uri is not a string")
		}

		// Because we're iterating over a map from the API response,
		// the order is random and some elements there do not contain the
		// `/beats/elastic-agent/` substring, so we need to go through the
		// whole map before returning an error.
		//
		// One of the elements that might be there and do not contain this
		// substring is the `elastic-agent-shipper`, whose URL is something like:
		// https://snapshots.elastic.co/8.7.0-d050210c/downloads/elastic-agent-shipper/elastic-agent-shipper-8.7.0-SNAPSHOT-linux-x86_64.tar.gz
		index := strings.Index(uri, "/beats/elastic-agent/")
		if index != -1 {
			return uri[:index], nil
		}
	}

	return "", fmt.Errorf("uri not detected")
}
