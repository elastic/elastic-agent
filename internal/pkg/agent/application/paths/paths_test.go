// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package paths

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEqual(t *testing.T) {
	isWindows := runtime.GOOS == "windows"
	testCases := []struct {
		Name        string
		Expected    string
		Actual      string
		ShouldMatch bool
	}{
		{"different paths", "/var/path/a", "/var/path/b", false},
		{"strictly same paths", "/var/path/a", "/var/path/a", true},
		{"strictly same win paths", `C:\Program Files\Elastic\Agent`, `C:\Program Files\Elastic\Agent`, true},
		{"case insensitive win paths", `C:\Program Files\Elastic\Agent`, `c:\Program Files\Elastic\Agent`, isWindows},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			assert.Equal(t, tc.ShouldMatch, ArePathsEqual(tc.Expected, tc.Actual))
		})
	}
}

func TestHasPrefixUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping unix HasPrefix tests on Windows host")
	}
	tests := map[string]struct {
		path   string
		prefix string
		want   bool
	}{
		"simple true":     {path: "/a/b", prefix: "/a", want: true},
		"just root":       {path: "/", prefix: "/", want: true},
		"root one dir":    {path: "/a", prefix: "/", want: true},
		"simple false":    {path: "/a/b", prefix: "/c/d", want: false},
		"prefix too long": {path: "/a/b", prefix: "/a/b/c/d", want: false},
		"trailing slash":  {path: "/a/b/", prefix: "/a", want: true},
		"no path":         {path: "", prefix: "/a", want: false},
		"no prefix":       {path: "/a/b", prefix: "", want: false},
		"middle differ":   {path: "/a/b/c", prefix: "/a/d/c", want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := HasPrefix(tc.path, tc.prefix)
			if got != tc.want {
				t.Fatalf("got %v, expected %v", got, tc.want)
			}
		})
	}
}

func TestHasPrefixWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Skipping windows HasPrefix tests on non Windows host")
	}
	tests := map[string]struct {
		path   string
		prefix string
		want   bool
	}{
		"simple true":      {path: "c:\\a\\b", prefix: "c:\\a", want: true},
		"just root":        {path: "c:\\", prefix: "c:\\", want: true},
		"root one dir":     {path: "c:\\a", prefix: "c:\\", want: true},
		"simple false":     {path: "c:\\a\\b", prefix: "c:\\c\\d", want: false},
		"prefix too long":  {path: "c:\\a\\b", prefix: "c:\\a\\b\\c\\d", want: false},
		"trailing slash":   {path: "c:\\a\\b\\", prefix: "c:\\a", want: true},
		"no path":          {path: "", prefix: "c:\\a", want: false},
		"no prefix":        {path: "c:\\a\\b", prefix: "", want: false},
		"case insensitive": {path: "C:\\A\\B", prefix: "c:\\a", want: true},
		"middle differ":    {path: "c:\\a\\b\\c", prefix: "c:\\a\\d\\c", want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := HasPrefix(tc.path, tc.prefix)
			if got != tc.want {
				t.Fatalf("got %v, expected %v", got, tc.want)
			}
		})
	}
}
