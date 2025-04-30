// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import "os"

// This test has nothing to do with the locally-built Agent artifact! It merely
// orchestrates resources in ECH (Elastic Cloud - Hosted). The purpose of this test
// is to ensure that a FIPS-capable Elastic Agent running in the ECH FRH (FedRamp High)
// environment is able to successfully connect to it's own local Fleet Server instance
// (which, by definition should also be FIPS-capable and running in the ECH FRH environment).

func TestFIPSAgentConnectingToFIPSFleetServerInECH(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Sudo:  false,
		Local: true,
	})

	// Re-use ECH API key used by integration tests to spin up a deployment
	// in ECH.
	for _, envVar := range os.Environ() {
		t.Log(envVar)
	}

	//The deployment must contain an Integrations Server, which includes
	// an Agent running with a local Fleet Server. Note that we want to use a
	// FIPS-capable build of Elastic Agent (with Fleet Server) for this deployment.
	// Further, the Fleet Server must be configured with FIPS-compliant TLS (TLSv1.2
	// and TLSv1.3 and appropriate ciphers).

	// Once the deployment is completely spun up, ensure that the Agent in the
	// deployment is healthy and connected to Fleet. This will prove that a FIPS-capable
	// Agent is able to connect to a FIPS-capable Fleet Server, with both running in ECH.
}
