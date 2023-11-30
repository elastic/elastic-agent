// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import "github.com/elastic/elastic-agent/pkg/testing/define"

const (
	// Default group.
	Default = define.Default

	// Fleet group of tests. Used for testing Elastic Agent with Fleet.
	Fleet = "fleet"

	// FleetUnprivileged group of tests. Used for testing Elastic Agent with Fleet installed unprivileged.
	FleetUnprivileged = "fleet-unprivileged"

	// FleetAirgapped group of tests. Used for testing Elastic Agent with Fleet and airgapped.
	FleetAirgapped = "fleet-airgapped"

	// FleetAirgappedUnprivileged group of tests. Used for testing Elastic Agent with Fleet installed
	// unprivileged and airgapped.
	FleetAirgappedUnprivileged = "fleet-airgapped-unprivileged"

	// Upgrade group of tests. Used for testing upgrades.
	Upgrade = "upgrade"

	// UpgradeUnprivileged group of tests. Used for testing upgrades installed unprivileged.
	UpgradeUnprivileged = "upgrade-unprivileged"
)
