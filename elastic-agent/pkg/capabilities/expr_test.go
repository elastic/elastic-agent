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

import (
	"fmt"
	"testing"

	"gotest.tools/assert"
)

func TestExpr(t *testing.T) {
	cases := []struct {
		Pattern     string
		Value       string
		ShouldMatch bool
	}{
		{"", "", true},
		{"*", "", true},
		{"*", "test", true},
		{"*", "system/test", true},
		{"system/*", "system/test", true},
		{"*/test", "system/test", true},
		{"*/*", "system/test", true},
		{"system/*", "agent/test", false},
		{"*/test", "test/system", false},
		{"*/test", "test", false},
		{"*/*", "test", false},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("testcase #%d", i), func(tt *testing.T) {
			match := matchesExpr(tc.Pattern, tc.Value)
			assert.Equal(t,
				tc.ShouldMatch,
				match,
				fmt.Sprintf("'%s' and '%s' and expecting should match: %v", tc.Pattern, tc.Value, tc.ShouldMatch),
			)
		})
	}
}
