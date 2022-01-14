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

package upgrade

import (
	"context"
	"strings"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/internal/pkg/artifact"
	"github.com/elastic/elastic-agent-poc/internal/pkg/artifact/download"
	"github.com/elastic/elastic-agent-poc/internal/pkg/artifact/download/composed"
	"github.com/elastic/elastic-agent-poc/internal/pkg/artifact/download/fs"
	"github.com/elastic/elastic-agent-poc/internal/pkg/artifact/download/http"
	downloader "github.com/elastic/elastic-agent-poc/internal/pkg/artifact/download/localremote"
	"github.com/elastic/elastic-agent-poc/internal/pkg/artifact/download/snapshot"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/internal/pkg/release"
)

func (u *Upgrader) downloadArtifact(ctx context.Context, version, sourceURI string) (string, error) {
	// do not update source config
	settings := *u.settings
	if sourceURI != "" {
		if strings.HasPrefix(sourceURI, "file://") {
			// update the DropPath so the fs.Downloader can download from this
			// path instead of looking into the installed downloads directory
			settings.DropPath = strings.TrimPrefix(sourceURI, "file://")
		} else {
			settings.SourceURI = sourceURI
		}
	}

	verifier, err := newVerifier(version, u.log, &settings)
	if err != nil {
		return "", errors.New(err, "initiating verifier")
	}

	fetcher, err := newDownloader(version, u.log, &settings)
	if err != nil {
		return "", errors.New(err, "initiating fetcher")
	}

	path, err := fetcher.Download(ctx, agentSpec, version)
	if err != nil {
		return "", errors.New(err, "failed upgrade of agent binary")
	}

	matches, err := verifier.Verify(agentSpec, version, true)
	if err != nil {
		return "", errors.New(err, "failed verification of agent binary")
	}
	if !matches {
		return "", errors.New("failed verification of agent binary, hash does not match", errors.TypeSecurity)
	}

	return path, nil
}

func newDownloader(version string, log *logger.Logger, settings *artifact.Config) (download.Downloader, error) {
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		return downloader.NewDownloader(log, settings)
	}

	// try snapshot repo before official
	snapDownloader, err := snapshot.NewDownloader(settings, version)
	if err != nil {
		return nil, err
	}

	httpDownloader, err := http.NewDownloader(settings)
	if err != nil {
		return nil, err
	}

	return composed.NewDownloader(fs.NewDownloader(settings), snapDownloader, httpDownloader), nil
}

func newVerifier(version string, log *logger.Logger, settings *artifact.Config) (download.Verifier, error) {
	allowEmptyPgp, pgp := release.PGP()
	if !strings.HasSuffix(version, "-SNAPSHOT") {
		return downloader.NewVerifier(log, settings, allowEmptyPgp, pgp)
	}

	fsVerifier, err := fs.NewVerifier(settings, allowEmptyPgp, pgp)
	if err != nil {
		return nil, err
	}

	snapshotVerifier, err := snapshot.NewVerifier(settings, allowEmptyPgp, pgp, version)
	if err != nil {
		return nil, err
	}

	remoteVerifier, err := http.NewVerifier(settings, allowEmptyPgp, pgp)
	if err != nil {
		return nil, err
	}

	return composed.NewVerifier(fsVerifier, snapshotVerifier, remoteVerifier), nil
}
