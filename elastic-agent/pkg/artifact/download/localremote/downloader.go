// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package localremote

import (
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/artifact"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/artifact/download"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/artifact/download/composed"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/artifact/download/fs"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/artifact/download/http"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/artifact/download/snapshot"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/release"
)

// NewDownloader creates a downloader which first checks local directory
// and then fallbacks to remote if configured.
func NewDownloader(log *logger.Logger, config *artifact.Config) (download.Downloader, error) {
	downloaders := make([]download.Downloader, 0, 3)
	downloaders = append(downloaders, fs.NewDownloader(config))

	// try snapshot repo before official
	if release.Snapshot() {
		snapDownloader, err := snapshot.NewDownloader(config, "")
		if err != nil {
			log.Error(err)
		} else {
			downloaders = append(downloaders, snapDownloader)
		}
	}

	httpDownloader, err := http.NewDownloader(config)
	if err != nil {
		return nil, err
	}

	downloaders = append(downloaders, httpDownloader)
	return composed.NewDownloader(downloaders...), nil
}
