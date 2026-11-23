// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package reexec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestReExecPreconditions locks in the matrix that distinguishes RESTART from
// UPGRADE after the gate was split: a RESTART only requires the agent to run
// under a supervisor (so DEB/RPM agents qualify), while an UPGRADE additionally
// requires the installed layout. The release-level upgrade flag forces
// upgradeability regardless of the other checks.
func TestReExecPreconditions(t *testing.T) {
	tests := []struct {
		name          string
		installed     bool
		supervised    bool
		releaseUpgrad bool

		wantReExec  bool
		wantRestart bool
		wantUpgrade bool
	}{
		{
			name:        "installed service (install sub-command)",
			installed:   true,
			supervised:  true,
			wantReExec:  true,
			wantRestart: true,
			wantUpgrade: true,
		},
		{
			name:        "DEB/RPM: supervised but not installed layout",
			installed:   false,
			supervised:  true,
			wantReExec:  true,
			wantRestart: true,  // restart allowed for DEB/RPM
			wantUpgrade: false, // upgrade still requires the installed layout
		},
		{
			name:        "container/PID1 or interactive binary: not supervised",
			installed:   false,
			supervised:  false,
			wantReExec:  false,
			wantRestart: false,
			wantUpgrade: false,
		},
		{
			name:        "installed layout present but not supervised",
			installed:   true,
			supervised:  false,
			wantReExec:  false,
			wantRestart: false,
			wantUpgrade: false, // needs supervisor as well
		},
		{
			name:          "release upgrade flag forces upgradeability",
			installed:     false,
			supervised:    false,
			releaseUpgrad: true,
			wantReExec:    false,
			wantRestart:   false,
			wantUpgrade:   true, // release flag short-circuits the other checks
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origInstalled := runningInstalled
			origSupervised := runningUnderSupervisor
			origUpgradeable := releaseUpgradeable
			t.Cleanup(func() {
				runningInstalled = origInstalled
				runningUnderSupervisor = origSupervised
				releaseUpgradeable = origUpgradeable
			})

			runningInstalled = func() bool { return tc.installed }
			runningUnderSupervisor = func() bool { return tc.supervised }
			releaseUpgradeable = func() bool { return tc.releaseUpgrad }

			assert.Equal(t, tc.wantReExec, CanReExec(), "CanReExec")
			assert.Equal(t, tc.wantRestart, CanRestart(), "CanRestart")
			assert.Equal(t, tc.wantUpgrade, CanUpgrade(), "CanUpgrade")
		})
	}
}
