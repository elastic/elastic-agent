// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIsHTTPUrl(t *testing.T) {

	tests := []struct {
		name string
		s    string
		res  bool
	}{
		{
			name: "empty",
		},
		{
			name: "/",
			s:    "/",
		},
		{
			name: "relative",
			s:    "foo/bar",
		},
		{
			name: "absolute",
			s:    "/foo/bar",
		},
		{
			name: "file",
			s:    "file://foo/bar",
		},
		{
			name: "http",
			s:    "http://localhost:5691",
			res:  true,
		},
		{
			name: "https",
			s:    "https://localhost:5691",
			res:  true,
		},
		{
			name: "http space prefix",
			s:    " http://localhost:5691",
			res:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := isHttpUrl(tc.s)
			diff := cmp.Diff(tc.res, res)
			if diff != "" {
				t.Error(diff)
			}
		})
	}
}
