// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"math"
	"time"
)

// Simple program that blocks forever to ensure exes running from a directory on Windows can be removed during uninstall.
func main() {
	<-time.After(time.Duration(math.MaxInt64))
}
