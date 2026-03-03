// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// rpmLockPaths lists known RPM database lock file locations.
var rpmLockPaths = []string{
	"/usr/lib/sysimage/rpm/.rpm.lock",
	"/var/lib/rpm/.rpm.lock",
}

// TestRpmLockContention repeatedly installs and uninstalls the RPM package
// to reproduce RPM database lock contention issues. A background goroutine
// continuously monitors the lock file so we can identify the culprit process
// when a conflict occurs.
func TestRpmLockContention(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.RPM,
		OS: []define.OS{
			{
				Type:   define.Linux,
				Distro: "rhel",
			},
		},
		Local: false,
		Sudo:  true,
	})

	const iterations = 50

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(30*time.Minute))
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithPackageFormat("rpm"))
	require.NoError(t, err)

	err = agentFixture.EnsurePrepared(ctx)
	require.NoError(t, err)

	srcPackage, err := agentFixture.SrcPackage(ctx)
	require.NoError(t, err)

	// Start background lock monitor.
	var mu sync.Mutex
	var lockEvents []string
	monitorCtx, monitorCancel := context.WithCancel(ctx)
	defer monitorCancel()

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-monitorCtx.Done():
				return
			case <-ticker.C:
				for _, lockPath := range rpmLockPaths {
					out, err := exec.CommandContext(monitorCtx, "sudo", "fuser", "-v", lockPath).CombinedOutput() // #nosec G204
					if err == nil && len(strings.TrimSpace(string(out))) > 0 {
						entry := time.Now().Format(time.RFC3339) + " " + lockPath + ":\n" + string(out)
						mu.Lock()
						lockEvents = append(lockEvents, entry)
						mu.Unlock()
					}
				}
			}
		}
	}()

	dumpDiagnostics := func(operation string, rpmErr error, rpmOut []byte) {
		t.Logf("=== RPM lock contention detected during %s ===", operation)
		t.Logf("rpm error: %v", rpmErr)
		t.Logf("rpm output: %s", string(rpmOut))

		// Dump current lock holders.
		for _, lockPath := range rpmLockPaths {
			out, err := exec.Command("sudo", "fuser", "-v", lockPath).CombinedOutput() // #nosec G204
			if err == nil && len(out) > 0 {
				t.Logf("fuser -v %s:\n%s", lockPath, string(out))
			}
		}

		// Dump timers and running services.
		for _, cmd := range []struct {
			name string
			args []string
		}{
			{"systemctl list-timers", []string{"systemctl", "list-timers", "--all", "--no-pager"}},
			{"systemctl active units", []string{"systemctl", "list-units", "--state=running", "--no-pager"}},
			{"ps aux", []string{"ps", "aux"}},
		} {
			out, err := exec.Command("sudo", cmd.args...).CombinedOutput() // #nosec G204
			if err != nil {
				t.Logf("%s: error: %v", cmd.name, err)
			} else {
				t.Logf("%s:\n%s", cmd.name, string(out))
			}
		}

		// Dump background monitor observations.
		mu.Lock()
		events := make([]string, len(lockEvents))
		copy(events, lockEvents)
		mu.Unlock()

		if len(events) > 0 {
			t.Logf("=== Background lock monitor observed %d events ===", len(events))
			for _, e := range events {
				t.Log(e)
			}
		} else {
			t.Log("Background lock monitor observed no lock holders")
		}

		t.Log("=== end RPM lock contention diagnostics ===")
	}

	for i := range iterations {
		t.Logf("--- iteration %d/%d ---", i+1, iterations)

		// Install
		out, err := exec.CommandContext(ctx, "sudo", "rpm", "-i", "-v", srcPackage).CombinedOutput() // #nosec G204
		if err != nil {
			dumpDiagnostics("install", err, out)
			t.Fatalf("rpm install failed on iteration %d: %v\noutput: %s", i+1, err, string(out))
		}

		// Stop the agent service before uninstalling.
		stopOut, stopErr := exec.CommandContext(ctx, "sudo", "systemctl", "stop", "elastic-agent").CombinedOutput()
		if stopErr != nil {
			t.Logf("systemctl stop elastic-agent: %v, output: %s", stopErr, string(stopOut))
		}

		// Uninstall
		out, err = exec.CommandContext(ctx, "sudo", "rpm", "-e", "elastic-agent").CombinedOutput() // #nosec G204
		if err != nil {
			dumpDiagnostics("uninstall", err, out)
			t.Fatalf("rpm uninstall failed on iteration %d: %v\noutput: %s", i+1, err, string(out))
		}

		// Clean up leftover files.
		_, _ = exec.CommandContext(ctx, "sudo", "rm", "-rf", "/var/lib/elastic-agent", "/var/log/elastic-agent", "/etc/elastic-agent").CombinedOutput()
	}

	monitorCancel()
	mu.Lock()
	defer mu.Unlock()
	if len(lockEvents) > 0 {
		t.Logf("=== Background lock monitor observed %d total events across all iterations ===", len(lockEvents))
		for _, e := range lockEvents {
			t.Log(e)
		}
	} else {
		t.Log("No lock holders observed by background monitor across all iterations")
	}
}
