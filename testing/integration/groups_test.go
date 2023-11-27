// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import "github.com/elastic/elastic-agent/pkg/testing/define"

const (
	// Default group.
	Default = define.Default

	// Endpoint group of tests. Used for testing endpoint inside of Elastic Agent.
	Endpoint = "endpoint"

	// Fleet group of tests. Used for testing Elastic Agent with Fleet.
	Fleet = "fleet"

	// FleetAirgapped group of tests. Used for testing Elastic Agent with Fleet and airgapped.
	FleetAirgapped = "fleet-airgapped"

	// Upgrade group of tests. Used for testing upgrades.
	Upgrade = "upgrade"
)
