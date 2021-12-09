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

package artifact

import (
	"fmt"
	"path/filepath"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/program"
)

var packageArchMap = map[string]string{
	"linux-binary-32":    "linux-x86.tar.gz",
	"linux-binary-64":    "linux-x86_64.tar.gz",
	"linux-binary-arm64": "linux-arm64.tar.gz",
	"windows-binary-32":  "windows-x86.zip",
	"windows-binary-64":  "windows-x86_64.zip",
	"darwin-binary-32":   "darwin-x86_64.tar.gz",
	"darwin-binary-64":   "darwin-x86_64.tar.gz",
}

// GetArtifactName constructs a path to a downloaded artifact
func GetArtifactName(spec program.Spec, version, operatingSystem, arch string) (string, error) {
	key := fmt.Sprintf("%s-binary-%s", operatingSystem, arch)
	suffix, found := packageArchMap[key]
	if !found {
		return "", errors.New(fmt.Sprintf("'%s' is not a valid combination for a package", key), errors.TypeConfig)
	}

	return fmt.Sprintf("%s-%s-%s", spec.Cmd, version, suffix), nil
}

// GetArtifactPath returns a full path of artifact for a program in specific version
func GetArtifactPath(spec program.Spec, version, operatingSystem, arch, targetDir string) (string, error) {
	artifactName, err := GetArtifactName(spec, version, operatingSystem, arch)
	if err != nil {
		return "", err
	}

	fullPath := filepath.Join(targetDir, artifactName)
	return fullPath, nil
}
