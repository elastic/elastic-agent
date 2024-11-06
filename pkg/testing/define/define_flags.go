// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package define

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

type optionalBoolFlag struct {
	value *bool
}

func (o *optionalBoolFlag) String() string {
	if o.value == nil {
		return "nil"
	}
	return strconv.FormatBool(*o.value)
}

func (o *optionalBoolFlag) Set(s string) error {
	bValue := s == "" || s == "true"
	o.value = &bValue
	return nil
}

type stringArrayFlag struct {
	values []string
}

func (s *stringArrayFlag) String() string {
	return fmt.Sprintf("%s", s.values)
}

func (s *stringArrayFlag) Set(stringValue string) error {
	if stringValue == "" {
		return nil
	}
	s.values = strings.Split(stringValue, ",")
	return nil
}

var (
	DryRun          bool
<<<<<<< HEAD
	GroupsFilter    []string
	PlatformsFilter []string
	SudoFilter      optionalBoolFlag

	groupStringFlag    string
	platformStringFlag string
=======
	GroupsFilter    stringArrayFlag
	PlatformsFilter stringArrayFlag
	SudoFilter      optionalBoolFlag
>>>>>>> 79781899da8feaf2fba61fa63e897b11fbb25fdc
)

func RegisterFlags(prefix string, set *flag.FlagSet) {
	set.BoolVar(&DryRun, prefix+"dry-run", false, "Forces test in dry-run mode: skips the main test and puts a successful placeholder <TestName>/dry-run if the test would have run")
<<<<<<< HEAD
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
	return strings.Split(stringFlag, ",")
}

=======
	set.Var(&GroupsFilter, prefix+"groups", "test groups, comma-separated")
	set.Var(&PlatformsFilter, prefix+"platforms", "test platforms, comma-separated")
	set.Var(&SudoFilter, prefix+"sudo", "Filter tests by sudo requirements")
}

>>>>>>> 79781899da8feaf2fba61fa63e897b11fbb25fdc
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
	t.Skip("Skipped because dry-run mode has been specified.")
	return nil
}
