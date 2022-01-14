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

package composed

import (
	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/program"
	"github.com/elastic/elastic-agent-poc/internal/pkg/artifact/download"
)

// Verifier is a verifier with a predefined set of verifiers.
// During each verify call it tries to call the first one and on failure fallbacks to
// the next one.
// Error is returned if all of them fail.
type Verifier struct {
	vv []download.Verifier
}

// NewVerifier creates a verifier composed out of predefined set of verifiers.
// During each verify call it tries to call the first one and on failure fallbacks to
// the next one.
// Error is returned if all of them fail.
func NewVerifier(verifiers ...download.Verifier) *Verifier {
	return &Verifier{
		vv: verifiers,
	}
}

// Verify checks the package from configured source.
func (e *Verifier) Verify(spec program.Spec, version string, removeOnFailure bool) (bool, error) {
	var err error

	for _, v := range e.vv {
		b, e := v.Verify(spec, version, removeOnFailure)
		if e == nil {
			return b, nil
		}

		err = multierror.Append(err, e)
	}

	return false, err
}
