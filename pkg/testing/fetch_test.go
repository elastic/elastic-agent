// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"errors"
	gtesting "testing"
)

func TestGetPackageSuffix(t *gtesting.T) {
	tests := map[string]struct {
		os       string
		arch     string
		format   string
		expected string
		err      error
	}{
		"windows zip":       {os: "windows", arch: "amd64", format: "zip", expected: "windows-x86_64.zip", err: nil},
		"windows msi":       {os: "windows", arch: "amd64", format: "msi", expected: "", err: ErrUnsupportedPlatform},
		"linux deb":         {os: "linux", arch: "amd64", format: "deb", expected: "amd64.deb", err: nil},
		"linux rpm":         {os: "linux", arch: "amd64", format: "rpm", expected: "x86_64.rpm", err: nil},
		"linux tar.gz":      {os: "linux", arch: "amd64", format: "targz", expected: "linux-x86_64.tar.gz", err: nil},
		"linux pkg.tar.zst": {os: "linux", arch: "amd64", format: "pkg.tar.zst", expected: "", err: ErrUnsupportedPlatform},
		"darwin arm64":      {os: "darwin", arch: "arm64", format: "targz", expected: "darwin-aarch64.tar.gz", err: nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *gtesting.T) {
			got, err := GetPackageSuffix(tc.os, tc.arch, tc.format)
			if !errors.Is(err, tc.err) {
				t.Fatalf("wrong error.  expected: %v got: %v", tc.err, err)
			}
			if got != tc.expected {
				t.Fatalf("wrong output. expected: %s got: %s", tc.expected, got)
			}
		})
	}
}
