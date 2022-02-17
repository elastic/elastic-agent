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
	"github.com/elastic/elastic-agent/internal/pkg/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/artifact/download/composed"
	"github.com/elastic/elastic-agent/internal/pkg/artifact/download/fs"
	"github.com/elastic/elastic-agent/internal/pkg/artifact/download/http"
	"github.com/elastic/elastic-agent/internal/pkg/artifact/download/snapshot"
	"github.com/elastic/elastic-agent/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

// NewVerifier creates a downloader which first checks local directory
// and then fallbacks to remote if configured.
func NewVerifier(log *logger.Logger, config *artifact.Config, allowEmptyPgp bool, pgp []byte) (download.Verifier, error) {
	verifiers := make([]download.Verifier, 0, 3)

	fsVer, err := fs.NewVerifier(config, allowEmptyPgp, pgp)
	if err != nil {
		return nil, err
	}
	verifiers = append(verifiers, fsVer)

	// try snapshot repo before official
	if release.Snapshot() {
		snapshotVerifier, err := snapshot.NewVerifier(config, allowEmptyPgp, pgp, "")
		if err != nil {
			log.Error(err)
		} else {
			verifiers = append(verifiers, snapshotVerifier)
		}
	}

	remoteVer, err := http.NewVerifier(config, allowEmptyPgp, pgp)
	if err != nil {
		return nil, err
	}
	verifiers = append(verifiers, remoteVer)

	return composed.NewVerifier(verifiers...), nil
}
