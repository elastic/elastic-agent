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

package capabilities

import "strings"

const (
	wild      = "*"
	separator = "/"
)

func matchesExpr(pattern, target string) bool {
	if pattern == wild {
		return true
	}

	patternParts := strings.Split(pattern, separator)
	targetParts := strings.Split(target, separator)

	if len(patternParts) != len(targetParts) {
		return false
	}

	for i, pp := range patternParts {
		if pp == wild {
			continue
		}

		if pp != targetParts[i] {
			return false
		}
	}

	return true
}
