// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package release

import "testing"

func TestSelectLatestReleaseBefore(t *testing.T) {
	versions := []string{"9.4.0", "9.4.3", "9.5.0", "v9.3.2", "8.19.1", "not-a-version"}
	got, err := selectLatestReleaseBefore(versions, "9.5.0")
	if err != nil {
		t.Fatalf("selectLatestReleaseBefore() error = %v", err)
	}
	if got != "9.4.3" {
		t.Errorf("selectLatestReleaseBefore() = %s, want 9.4.3", got)
	}
}

func TestInferNextProjectMinorVersion(t *testing.T) {
	got, err := inferNextProjectMinorVersion("9.5.0")
	if err != nil {
		t.Fatalf("inferNextProjectMinorVersion() error = %v", err)
	}
	if got != "9.6.0" {
		t.Errorf("inferNextProjectMinorVersion() = %s, want 9.6.0", got)
	}
}
