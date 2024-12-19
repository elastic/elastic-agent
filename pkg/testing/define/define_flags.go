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
	DryRun              bool
	GroupsFilter        stringArrayFlag
	PlatformsFilter     stringArrayFlag
	SudoFilter          optionalBoolFlag
	AutoDiscover        bool
	AutoDiscoveryOutput string
)

func RegisterFlags(prefix string, set *flag.FlagSet) {
	set.BoolVar(&DryRun, prefix+"dry-run", false, "Forces test in dry-run mode: skips the main test and puts a successful placeholder <TestName>/dry-run if the test would have run")
	set.Var(&GroupsFilter, prefix+"groups", "test groups, comma-separated")
	set.Var(&PlatformsFilter, prefix+"platforms", "test platforms, comma-separated")
	set.Var(&SudoFilter, prefix+"sudo", "Filter tests by sudo requirements")
	set.BoolVar(&AutoDiscover, prefix+"autodiscover", false, "Auto discover tests (should be used together with -dry-run). Output will be a file that can be set with -autodiscoveryoutput")
	set.StringVar(&AutoDiscoveryOutput, prefix+"autodiscoveryoutput", "discovered_tests.yaml", "Set the file location where the structured output for the discovered tests will be stored")
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
	t.Skip("Skipped because dry-run mode has been specified.")
	return nil
}
