// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration && frh

package integration

import (
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

// IMPORTANT: This file has build tags of integration && frh. This means the tests in
// this file will NOT be run along with other integration tests (which use deployments
// in the ESS production CFT region). The tests in this file need to be run using
// deployments in an ECH FRH (FedRamp High) region. This region can be specified using
// the following environment variables:
// TEST_INTEG_AUTH_ESS_FRH_URL (default: https://api.staging.elastic-gov.com/)
// TEST_INTEG_AUTH_ESS_FRH_REGION (default: us-gov-east-1)
// TEST_INTEG_AUTH_ESS_FRH_APIKEY

// TestFIPSAgentConnectingToFIPSFleetServerInECHFRH ensures that a FIPS-capable Elastic Agent
// running in an ECH FRH (FedRamp High) environment is able to successfully connect to its
// own local Fleet Server instance (which, by definition should also be FIPS-capable and
// running in the ECH FRH environment).
// NOTE: This test has nothing to do with the locally-built Agent artifact! It merely
// orchestrates resources in ECH (Elastic Cloud - Hosted).

func TestFIPSAgentConnectingToFIPSFleetServerInECHFRH(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: nil,
		Sudo:  false,
		Local: true,
	})

	// Connect to ECH FRH environment and spin up deployment. The deployment must
	// contain an Integrations Server, which includes an Agent running with a local
	// Fleet Server. Note that we will need to use a FIPS-capable build of Elastic Agent
	// (with Fleet Server) for this deployment. Further, the Fleet Server must be configured with FIPS-compliant TLS (TLSv1.2
	// and TLSv1.3 and appropriate ciphers).

	// Once the deployment is completely spun up, ensure that the Agent in the
	// deployment is healthy and connected to Fleet. This will prove that a FIPS-capable
	// Agent is able to connect to a FIPS-capable Fleet Server, with both running in ECH.
}
