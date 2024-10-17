// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package define

import (
	"flag"
	"fmt"
	"os"
	"strings"
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
	trimmed := strings.Trim(stringFlag, " ")
	fmt.Fprintf(os.Stderr, "Splitting %q...", trimmed)
	return strings.Split(trimmed, ",")
}
