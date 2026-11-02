// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !edr

package component

// flavorAllowedInputTypes is empty for standard builds, meaning no
// input-type restriction is applied.
var flavorAllowedInputTypes map[string]struct{}
