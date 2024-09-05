// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package localremote

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/composed"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/fs"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/http"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/snapshot"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// NewDownloader creates a downloader which first checks local directory
// and then fallbacks to remote if configured.
func NewDownloader(log *logger.Logger, config *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
	downloaders := make([]download.Downloader, 0, 3)
	downloaders = append(downloaders, fs.NewDownloader(config))

	// If the current build is a snapshot we use this downloader to update
	// to the latest snapshot of the same version. Useful for testing with
	// a snapshot version of fleet, for example.
	// try snapshot repo before official
	if release.Snapshot() {
		snapDownloader, err := snapshot.NewDownloader(log, config, nil, upgradeDetails)
		if err != nil {
			log.Error(err)
		} else {
			downloaders = append(downloaders, snapDownloader)
		}
	}

	httpDownloader, err := http.NewDownloader(log, config, upgradeDetails)
	if err != nil {
		return nil, err
	}

	downloaders = append(downloaders, httpDownloader)
	return composed.NewDownloader(downloaders...), nil
}
