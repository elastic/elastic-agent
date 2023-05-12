// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ess

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOverallStatus(t *testing.T) {
	tests := map[string]struct {
		statuses              []DeploymentStatus
		expectedOverallStatus DeploymentStatus
	}{
		"single_started": {
			statuses:              []DeploymentStatus{DeploymentStatusStarted},
			expectedOverallStatus: DeploymentStatusStarted,
		},
		"single_not_started": {
			statuses:              []DeploymentStatus{DeploymentStatusReconfiguring},
			expectedOverallStatus: DeploymentStatusReconfiguring,
		},
		"multiple_none_started": {
			statuses:              []DeploymentStatus{DeploymentStatusInitializing, DeploymentStatusReconfiguring},
			expectedOverallStatus: DeploymentStatusInitializing,
		},
		"multiple_some_started": {
			statuses:              []DeploymentStatus{DeploymentStatusReconfiguring, DeploymentStatusStarted, DeploymentStatusInitializing},
			expectedOverallStatus: DeploymentStatusReconfiguring,
		},
		"multiple_all_started": {
			statuses:              []DeploymentStatus{DeploymentStatusStarted, DeploymentStatusStarted, DeploymentStatusStarted},
			expectedOverallStatus: DeploymentStatusStarted,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actual := overallStatus(test.statuses...)
			require.Equal(t, test.expectedOverallStatus, actual)
		})
	}
}
