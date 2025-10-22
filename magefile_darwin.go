// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build mage && darwin

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/magefile/mage/sh"
)

func osMajorVersion() (int, error) {
	ver, err := sh.Output("sw_vers", "-productVersion")
	if err != nil {
		return 0, err
	}

	majorVerStr := strings.Split(ver, ".")[0]
	majorVer, err := strconv.Atoi(majorVerStr)
	if err != nil {
		return 0, fmt.Errorf("unable to parse major version from %q: %w", ver, err)
	}

	return majorVer, nil
}
