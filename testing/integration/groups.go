// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import "github.com/elastic/elastic-agent/pkg/testing/define"

const (
	// Default group.
	Default = define.Default

	// ECH group of tests. Used to test against a custom integration server.
	ECH = "ech"

	// Fleet group of tests. Used for testing Elastic Agent with Fleet.
	Fleet = "fleet"

	// FleetUpgrade group of tests. Used for testing Fleet-managed upgrades (including
	// rollbacks and download settings). Split out of Fleet to keep CI groups short.
	FleetUpgrade = "fleet-upgrade"

	// FleetProxy group of tests. Used for testing Fleet communication through proxies,
	// check-in behaviour and policy change persistence. Split out of Fleet to keep CI
	// groups short.
	FleetProxy = "fleet-proxy"

	// Container group of tests. Used for testing Elastic Agent in container mode.
	Container = "container"

	// FleetPrivileged group of tests. Used for testing Elastic Agent with Fleet installed privileged.
	FleetPrivileged = "fleet-privileged"

	// FleetAirgapped group of tests. Used for testing Elastic Agent with Fleet and airgapped.
	FleetAirgapped = "fleet-airgapped"

	// FleetAirgappedPrivileged group of tests. Used for testing Elastic Agent with Fleet installed
	// privileged and airgapped.
	FleetAirgappedPrivileged = "fleet-airgapped-privileged"

	// FleetUpgradeToPRBuild group of tests. Used for testing Elastic Agent
	// upgrading to a build built from the PR being tested.
	FleetUpgradeToPRBuild = "fleet-upgrade-to-pr-build"

	// Hostname group of tests. Used for testing Elastic Agent hostname behaviour (FQDN, env override).
	Hostname = "hostname"

	// Upgrade group of tests. Used for testing upgrades.
	Upgrade = "upgrade"

	// UpgradeRollback group of tests. Used for the long running standalone rollback
	// tests. Split out of Upgrade to keep CI groups short.
	UpgradeRollback = "upgrade-rollback"

	// UpgradeFlavor group of tests. Used for testing flavored upgrades.
	UpgradeFlavor = "upgrade-flavor"

	// StandaloneUpgrade group of tests. Used for TestStandaloneUpgrade (privileged).
	StandaloneUpgrade = "standalone-upgrade"

	// StandaloneUpgradeUnprivileged group of tests. Used for TestStandaloneUpgradeUnprivileged.
	// Split out of StandaloneUpgrade to keep CI groups short.
	StandaloneUpgradeUnprivileged = "standalone-upgrade-unprivileged"

	// Deb group of tests. Used for testing .deb packages install & upgrades
	Deb = "deb"

	// RPM group of tests. Used for testing .rpm packages install & upgrades
	RPM = "rpm"

	// InstallUninstall group of tests. Used for testing repeated install & uninstall scenarios
	InstallUninstall = "install-uninstall"

	// FleetEndpointSecurity group of tests. Used for the long running fleet-related "TestInstall..." tests.
	FleetEndpointSecurity = "fleet-endpoint-security"

	// FleetEndpointSecurityMTLS group of tests. Used for TestInstallDefendWithMTLSandEncCertKey,
	// which alone takes as long as the rest of FleetEndpointSecurity. Split out to keep CI groups short.
	FleetEndpointSecurityMTLS = "fleet-endpoint-security-mtls"

	// ECHDeployment group of tests. Used for tests that orchestrate ECH deployments.
	ECHDeployment = "ech-deployment"

	// Stress test suite that contains tests that do not need to run on each PR.
	Stress = "stress"
)
