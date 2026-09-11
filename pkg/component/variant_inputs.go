// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !securityonly

package component

// variantAllowedInputTypes is empty for standard builds, meaning no
// input-type restriction is applied.
var variantAllowedInputTypes map[string]struct{}
