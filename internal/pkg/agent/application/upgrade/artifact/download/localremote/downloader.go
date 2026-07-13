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
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

// NewDownloader creates a downloader which first checks local directory
// and then fallbacks to remote if configured.
func NewDownloader(log *logger.Logger, config *artifact.Config, upgradeDetails *details.Details) (download.Downloader, error) {
	downloaders := make([]download.Downloader, 0, 2)
	downloaders = append(downloaders, fs.NewDownloader(config))

	httpDownloader, err := http.NewDownloader(log, config, upgradeDetails)
	if err != nil {
		return nil, err
	}

	downloaders = append(downloaders, httpDownloader)
	return composed.NewDownloader(downloaders...), nil
}
