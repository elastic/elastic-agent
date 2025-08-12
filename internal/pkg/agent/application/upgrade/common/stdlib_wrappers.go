// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import (
	"io"
	"os"
)

// The following are wrappers for stdlib functions so that we can mock them in tests.
var Copy = io.Copy
var OpenFile = os.OpenFile
var MkdirAll = os.MkdirAll
