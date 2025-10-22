// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build mage && !darwin

package main

func osVersion() (string, error) {
	// Not needed for OSes other than macOS
	return "", nil
}
