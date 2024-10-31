// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package define

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
)

var (
	DryRun    bool
	Groups    []string
	Platforms []string

	groupStringFlag    string
	platformStringFlag string
)

func RegisterFlags(prefix string, set *flag.FlagSet) {
	set.BoolVar(&DryRun, prefix+"dry-run", false, "Forces test in dry-run mode: drops platform/group/sudo requirements")
	set.StringVar(&groupStringFlag, prefix+"groups", "", "test groups, comma-separated")
	set.StringVar(&platformStringFlag, prefix+"platforms", "", "test platforms, comma-separated")
}

func ParseFlags() {
	Groups = splitStringToArray(groupStringFlag)
	Platforms = splitStringToArray(platformStringFlag)
}

func splitStringToArray(stringFlag string) []string {
	if stringFlag == "" {
		return nil
	}
	fmt.Fprintf(os.Stderr, "Splitting %q...", stringFlag)
	return strings.Split(stringFlag, ",")
}

func dryRun(t *testing.T, req Requirements) *Info {
	// always validate requirement is valid
	if err := req.Validate(); err != nil {
		t.Logf("test %s has invalid requirements: %s", t.Name(), err)
		t.FailNow()
		return nil
	}
	// skip the test as we are in dry run
	t.Run("dry-run", func(t *testing.T) {
		t.Log("Test dry-run successful")
	})
	t.Skip(fmt.Sprintf("Skipped because dry-run mode has been specified."))
	return nil
}
