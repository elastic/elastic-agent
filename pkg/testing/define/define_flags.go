// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package define

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

type optionalBoolFlag struct {
	set   bool
	value bool
}

func (o *optionalBoolFlag) String() string {
	if !o.set {
		return "<not set>"
	}
	return strconv.FormatBool(o.value)
}

func (o *optionalBoolFlag) Set(s string) error {
	o.set = true
	if s == "" || s == "true" {
		o.value = true
		return nil
	}
	o.value = false
	return nil
}

func (o *optionalBoolFlag) HasBeenSet() bool {
	return o.set
}

func (o *optionalBoolFlag) Value() bool {
	return o.value
}

var (
	DryRun          bool
	GroupsFilter    []string
	PlatformsFilter []string
	SudoFilter      optionalBoolFlag

	groupStringFlag    string
	platformStringFlag string
)

func RegisterFlags(prefix string, set *flag.FlagSet) {
	set.BoolVar(&DryRun, prefix+"dry-run", false, "Forces test in dry-run mode: skips the main test and puts a successful placeholder <TestName>/dry-run if the test would have run")
	set.StringVar(&groupStringFlag, prefix+"groups", "", "test groups, comma-separated")
	set.StringVar(&platformStringFlag, prefix+"platforms", "", "test platforms, comma-separated")
	set.Var(&SudoFilter, prefix+"sudo", "Filter tests by sudo requirements")
}

func ParseFlags() {
	GroupsFilter = splitStringToArray(groupStringFlag)
	PlatformsFilter = splitStringToArray(platformStringFlag)
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
