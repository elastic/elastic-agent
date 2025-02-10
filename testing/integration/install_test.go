// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	aTesting "github.com/elastic/elastic-agent/pkg/testing"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/installtest"
)

type componentPresenceDefinition struct {
	name      string
	platforms []string
}

func TestInstallWithoutBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		// We require sudo for this test to run
		// `elastic-agent install` (even though it will
		// be installed as non-root).
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	testInstallWithoutBasePathWithCustomUser(ctx, t, fixture, "", "")
}

func TestInstallWithoutBasePathWithCustomUser(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		// We require sudo for this test to run
		// `elastic-agent install` (even though it will
		// be installed as non-root).
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
		OS: []define.OS{
			{
				Type: define.Darwin,
			}, {
				Type: define.Linux,
			},
		},
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	testInstallWithoutBasePathWithCustomUser(ctx, t, fixture, "tester", "testing")
}

func TestInstallWithBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		// We require sudo for this test to run
		// `elastic-agent install` (even though it will
		// be installed as non-root).
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	// When installing with unprivileged using a base path the
	// base needs to be accessible by the `elastic-agent-user` user that will be
	// executing the process, but is not created yet. Using a base that exists
	// and is known to be accessible by standard users, ensures this tests
	// works correctly and will not hit a permission issue when spawning the
	// elastic-agent service.
	var basePath string
	switch runtime.GOOS {
	case define.Linux:
		basePath = `/usr`
	case define.Windows:
		basePath = `C:\`
	default:
		// Set up random temporary directory to serve as base path for Elastic Agent
		// installation.
		tmpDir := t.TempDir()
		basePath = filepath.Join(tmpDir, strings.ToLower(randStr(8)))
	}

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	opts := atesting.InstallOpts{
		BasePath:   basePath,
		Force:      true,
		Privileged: false,
	}
	out, err := fixture.Install(ctx, &opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in the custom base path
	topPath := filepath.Join(basePath, "Elastic", "Agent")
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, &installtest.CheckOpts{Privileged: opts.Privileged}))

	t.Run("check agent package version", testAgentPackageVersion(ctx, fixture, true))
	t.Run("check second agent installs with --namespace", testSecondAgentCanInstall(ctx, fixture, basePath, false, opts))
	t.Run("check second agent can be installed again with --namespace --force", testSecondAgentCanInstallWithForce(ctx, fixture, basePath, false, opts))
	t.Run("check the initial agent is still installed and healthy", func(t *testing.T) {
		require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, &installtest.CheckOpts{Privileged: opts.Privileged}))
	})

	t.Run("check components set",
		testComponentsPresence(ctx, fixture,
			[]componentPresenceDefinition{
				{"agentbeat", []string{"windows", "linux", "darwin"}},
				{"endpoint-security", []string{"windows", "linux", "darwin"}},
				{"pf-host-agent", []string{"linux"}},
			},
			[]componentPresenceDefinition{
				{"cloudbeat", []string{"linux"}},
				{"apm-server", []string{"windows", "linux", "darwin"}},
				{"fleet-server", []string{"windows", "linux", "darwin"}},
				{"pf-elastic-symbolizer", []string{"linux"}},
				{"pf-elastic-collector", []string{"linux"}},
			}))

	// Make sure uninstall from within the topPath fails on Windows
	if runtime.GOOS == "windows" {
		cwd, err := os.Getwd()
		require.NoErrorf(t, err, "GetWd failed: %s", err)
		err = os.Chdir(topPath)
		require.NoErrorf(t, err, "Chdir to topPath failed: %s", err)
		t.Cleanup(func() {
			_ = os.Chdir(cwd)
		})
		out, err = fixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
		require.Error(t, err, "uninstall should have failed")
		require.Containsf(t, string(out), "uninstall must be run from outside the installed path", "expected error string not found in: %s err: %s", out, err)
	}
}

func TestInstallServersWithBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		// We require sudo for this test to run
		// `elastic-agent install` (even though it will
		// be installed as non-root).
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	// When installing with unprivileged using a base path the
	// base needs to be accessible by the `elastic-agent-user` user that will be
	// executing the process, but is not created yet. Using a base that exists
	// and is known to be accessible by standard users, ensures this tests
	// works correctly and will not hit a permission issue when spawning the
	// elastic-agent service.
	var basePath string
	switch runtime.GOOS {
	case define.Linux:
		basePath = `/usr`
	case define.Windows:
		basePath = `C:\`
	default:
		// Set up random temporary directory to serve as base path for Elastic Agent
		// installation.
		tmpDir := t.TempDir()
		basePath = filepath.Join(tmpDir, strings.ToLower(randStr(8)))
	}

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	opts := atesting.InstallOpts{
		BasePath:       basePath,
		Force:          true,
		Privileged:     false,
		InstallServers: true,
	}
	out, err := fixture.Install(ctx, &opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in the custom base path
	topPath := filepath.Join(basePath, "Elastic", "Agent")
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, &installtest.CheckOpts{Privileged: opts.Privileged}))

	t.Run("check agent package version", testAgentPackageVersion(ctx, fixture, true))
	t.Run("check second agent installs with --namespace", testSecondAgentCanInstall(ctx, fixture, basePath, false, opts))

	t.Run("check components set",
		testComponentsPresence(ctx, fixture,
			[]componentPresenceDefinition{
				{"agentbeat", []string{"windows", "linux", "darwin"}},
				{"endpoint-security", []string{"windows", "linux", "darwin"}},
				{"pf-host-agent", []string{"linux"}},
				{"cloudbeat", []string{"linux"}},
				{"apm-server", []string{"windows", "linux", "darwin"}},
				{"fleet-server", []string{"windows", "linux", "darwin"}},
				{"pf-elastic-symbolizer", []string{"linux"}},
				{"pf-elastic-collector", []string{"linux"}},
			},
			[]componentPresenceDefinition{}))

	// Make sure uninstall from within the topPath fails on Windows
	if runtime.GOOS == "windows" {
		cwd, err := os.Getwd()
		require.NoErrorf(t, err, "GetWd failed: %s", err)
		err = os.Chdir(topPath)
		require.NoErrorf(t, err, "Chdir to topPath failed: %s", err)
		t.Cleanup(func() {
			_ = os.Chdir(cwd)
		})
		out, err = fixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
		require.Error(t, err, "uninstall should have failed")
		require.Containsf(t, string(out), "uninstall must be run from outside the installed path", "expected error string not found in: %s err: %s", out, err)
	}
}

func TestInstallPrivilegedWithoutBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	opts := atesting.InstallOpts{Force: true, Privileged: true}
	out, err := fixture.Install(ctx, &opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in default base path
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, opts.BasePath, &installtest.CheckOpts{Privileged: opts.Privileged}))

	t.Run("check agent package version", testAgentPackageVersion(ctx, fixture, true))
	t.Run("check second agent installs with --namespace", testSecondAgentCanInstall(ctx, fixture, "", false, opts))
	t.Run("check second agent can be installed again with --namespace --force", testSecondAgentCanInstallWithForce(ctx, fixture, "", false, opts))
	t.Run("check the initial agent is still installed and healthy", func(t *testing.T) {
		require.NoError(t, installtest.CheckSuccess(ctx, fixture, opts.BasePath, &installtest.CheckOpts{Privileged: opts.Privileged}))
	})
}

func TestInstallPrivilegedWithBasePath(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		// We require sudo for this test to run
		// `elastic-agent install`.
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	// Set up random temporary directory to serve as base path for Elastic Agent
	// installation.
	tmpDir := t.TempDir()
	randomBasePath := filepath.Join(tmpDir, strings.ToLower(randStr(8)))

	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	opts := atesting.InstallOpts{
		BasePath:   randomBasePath,
		Force:      true,
		Privileged: true,
	}
	out, err := fixture.Install(ctx, &opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in the custom base path
	topPath := filepath.Join(randomBasePath, "Elastic", "Agent")
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, &installtest.CheckOpts{Privileged: opts.Privileged}))
	t.Run("check agent package version", testAgentPackageVersion(ctx, fixture, true))
	t.Run("check second agent installs with --develop", testSecondAgentCanInstall(ctx, fixture, randomBasePath, true, opts))
	t.Run("check second agent can be installed again with --develop --force", testSecondAgentCanInstallWithForce(ctx, fixture, randomBasePath, true, opts))
	t.Run("check the initial agent is still installed and healthy", func(t *testing.T) {
		require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, &installtest.CheckOpts{Privileged: opts.Privileged}))
	})
}

func testInstallWithoutBasePathWithCustomUser(ctx context.Context, t *testing.T, fixture *atesting.Fixture, customUsername, customGroup string) {
	// Run `elastic-agent install`.  We use `--force` to prevent interactive
	// execution.
	// create testing user
	if customUsername != "" {
		pt := progressbar.NewOptions(-1)
		_, err := install.EnsureUserAndGroup(customUsername, customGroup, pt, true)
		require.NoError(t, err)
	}

	opts := atesting.InstallOpts{Force: true, Privileged: false, Username: customUsername, Group: customGroup}
	out, err := fixture.Install(ctx, &opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	// Check that Agent was installed in default base path
	topPath := installtest.DefaultTopPath()
	checks := &installtest.CheckOpts{
		Privileged: opts.Privileged,
		Username:   customUsername,
		Group:      customGroup,
	}
	require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, checks))

	t.Run("check agent package version", testAgentPackageVersion(ctx, fixture, true))
	t.Run("check second agent installs with --develop", testSecondAgentCanInstall(ctx, fixture, "", true, opts))

	t.Run("check second agent can be installed again with --develop --force", testSecondAgentCanInstallWithForce(ctx, fixture, "", true, opts))
	t.Run("check the initial agent is still installed and healthy", func(t *testing.T) {
		require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, checks))
	})

	// Make sure uninstall from within the topPath fails on Windows
	if runtime.GOOS == "windows" {
		cwd, err := os.Getwd()
		require.NoErrorf(t, err, "GetWd failed: %s", err)
		err = os.Chdir(topPath)
		require.NoErrorf(t, err, "Chdir to topPath failed: %s", err)
		t.Cleanup(func() {
			_ = os.Chdir(cwd)
		})
		out, err = fixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
		require.Error(t, err, "uninstall should have failed")
		require.Containsf(t, string(out), "uninstall must be run from outside the installed path", "expected error string not found in: %s err: %s", out, err)
	}
}

func testComponentsPresence(ctx context.Context, fixture *atesting.Fixture, requiredComponents []componentPresenceDefinition, unwantedComponents []componentPresenceDefinition) func(*testing.T) {
	return func(t *testing.T) {
		agentWorkDir := fixture.WorkDir()
		componentsDir, err := aTesting.FindComponentsDir(agentWorkDir)
		require.NoError(t, err)

		componentsPaths := func(component string) []string {
			binarySuffix := ""
			if runtime.GOOS == "windows" {
				binarySuffix += ".exe"
			}
			return []string{
				filepath.Join(componentsDir, component+binarySuffix),
				filepath.Join(componentsDir, component+".spec.yml"),
			}
		}

		for _, requiredComponent := range requiredComponents {
			for _, reqPath := range componentsPaths(requiredComponent.name) {
				_, err := os.Stat(reqPath)
				if slices.Contains(requiredComponent.platforms, runtime.GOOS) {
					require.NoErrorf(t, err, "expecting component %q to be present: %v", requiredComponent, err)
				} else {
					require.ErrorIs(t, err, os.ErrNotExist, "expecting component %q to be missing but was found", requiredComponent)
				}
			}
		}

		for _, unwantedComponent := range unwantedComponents {
			for _, reqPath := range componentsPaths(unwantedComponent.name) {
				_, err := os.Stat(reqPath)
				require.ErrorIs(t, err, os.ErrNotExist, "expecting component %q to be missing but was found", unwantedComponent)
			}
		}
	}
}

func testSecondAgentCanInstallWithForce(ctx context.Context, fixture *atesting.Fixture, basePath string, develop bool, installOpts atesting.InstallOpts) func(*testing.T) {
	installOpts.Force = true
	return testSecondAgentCanInstall(ctx, fixture, basePath, develop, installOpts)
}

// Tests that a second agent can be installed in an isolated namespace, using either --develop or --namespace.
func testSecondAgentCanInstall(ctx context.Context, fixture *atesting.Fixture, basePath string, develop bool, installOpts atesting.InstallOpts) func(*testing.T) {
	return func(t *testing.T) {
		// Get path to Elastic Agent executable
		devFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		// Prepare the Elastic Agent so the binary is extracted and ready to use.
		err = devFixture.Prepare(ctx)
		require.NoError(t, err)

		// If development mode was requested, the namespace will be automatically set to Development after Install().
		// Otherwise, install into a test namespace.
		installOpts.Develop = develop
		if !installOpts.Develop {
			installOpts.Namespace = "Testing"
		}

		devOut, err := devFixture.Install(ctx, &installOpts)
		if err != nil {
			t.Logf("install output: %s", devOut)
			require.NoError(t, err)
		}

		topPath := installtest.NamespaceTopPath(installOpts.Namespace)
		if basePath != "" {
			topPath = filepath.Join(basePath, "Elastic", paths.InstallDirNameForNamespace(installOpts.Namespace))
		}

		require.NoError(t, installtest.CheckSuccess(ctx, fixture, topPath, &installtest.CheckOpts{
			Privileged: installOpts.Privileged,
			Namespace:  installOpts.Namespace,
			Username:   installOpts.Username,
			Group:      installOpts.Group,
		}))
	}
}

// TestInstallUninstallAudit will test to make sure that a fleet-managed agent can use the audit/unenroll endpoint when uninstalling itself.
func TestInstallUninstallAudit(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{}, // needs a fleet-server.
		Sudo:  true,
		Local: false,
		// Skip Windows as it has been disabled because of https://github.com/elastic/elastic-agent/issues/5952
		OS: []define.OS{
			{
				Type: define.Linux,
			},
			{
				Type: define.Darwin,
			},
		},
	})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	policyResp, enrollmentTokenResp := createPolicyAndEnrollmentToken(ctx, t, info.KibanaClient, createBasicPolicy())
	t.Logf("Created policy %+v", policyResp.AgentPolicy)

	t.Log("Getting default Fleet Server URL...")
	fleetServerURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	t.Run("privileged", func(t *testing.T) {
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		err = fixture.Prepare(ctx)
		require.NoError(t, err)
		// Run `elastic-agent install`.  We use `--force` to prevent interactive
		// execution.
		opts := &atesting.InstallOpts{
			Force:      true,
			Privileged: true,
			EnrollOpts: atesting.EnrollOpts{
				URL:             fleetServerURL,
				EnrollmentToken: enrollmentTokenResp.APIKey,
			},
		}
		out, err := fixture.Install(ctx, opts)
		if err != nil {
			t.Logf("install output: %s", out)
			require.NoError(t, err)
		}

		require.Eventuallyf(t, func() bool {
			return waitForAgentAndFleetHealthy(ctx, t, fixture)
		}, time.Minute, time.Second, "agent never became healthy or connected to Fleet")

		t.Run("run uninstall", testUninstallAuditUnenroll(ctx, fixture, info))
	})

	t.Run("unprivileged", func(t *testing.T) {
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		err = fixture.Prepare(ctx)
		require.NoError(t, err)
		// Run `elastic-agent install`.  We use `--force` to prevent interactive
		// execution.
		opts := &atesting.InstallOpts{
			Force:      true,
			Privileged: false,
			EnrollOpts: atesting.EnrollOpts{
				URL:             fleetServerURL,
				EnrollmentToken: enrollmentTokenResp.APIKey,
			},
		}
		out, err := fixture.Install(ctx, opts)
		if err != nil {
			t.Logf("install output: %s", out)
			require.NoError(t, err)
		}

		require.Eventuallyf(t, func() bool {
			return waitForAgentAndFleetHealthy(ctx, t, fixture)
		}, time.Minute, time.Second, "agent never became healthy or connected to Fleet")

		t.Run("run uninstall", testUninstallAuditUnenroll(ctx, fixture, info))
	})
}

func testUninstallAuditUnenroll(ctx context.Context, fixture *atesting.Fixture, info *define.Info) func(t *testing.T) {
	return func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Skip Windows as it has been disabled because of https://github.com/elastic/elastic-agent/issues/5952")
		}
		agentID, err := getAgentID(ctx, fixture)
		require.NoError(t, err, "error getting the agent inspect output")
		require.NotEmpty(t, agentID, "agent ID empty")

		out, err := fixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
		if err != nil {
			t.Logf("uninstall output: %s", out)
			require.NoError(t, err)
		}

		// TODO: replace direct query to ES index with API call to Fleet
		// Blocked on https://github.com/elastic/kibana/issues/194884
		response, err := info.ESClient.Get(".fleet-agents", agentID, info.ESClient.Get.WithContext(ctx))
		require.NoError(t, err)
		defer response.Body.Close()
		p, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equalf(t, http.StatusOK, response.StatusCode, "ES status code expected 200, body: %s", p)
		var res struct {
			Source struct {
				AuditUnenrolledReason string `json:"audit_unenrolled_reason"`
			} `json:"_source"`
		}
		err = json.Unmarshal(p, &res)
		require.NoError(t, err)
		require.Equalf(t, "uninstall", res.Source.AuditUnenrolledReason, "uninstall output: %s", out)
	}
}

// TestRepeatedInstallUninstallFleet will install then uninstall the agent
// repeatedly with it enrolled into Fleet.  This test exists because of a number
// of race conditions that have occurred in the uninstall process when enrolled
// into Fleet. Current testing shows each iteration takes around 16 seconds.
func TestRepeatedInstallUninstallFleet(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: InstallUninstall,
		Stack: &define.Stack{}, // needs a fleet-server.
		// We require sudo for this test to run
		// `elastic-agent install` (even though it will
		// be installed as non-root).
		Sudo: true,

		// It's not safe to run this test locally as it
		// installs Elastic Agent.
		Local: false,
	})

	prepareCtx, prepareCancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer prepareCancel()

	policyResp, enrollmentTokenResp := createPolicyAndEnrollmentToken(prepareCtx, t, info.KibanaClient, createBasicPolicy())
	t.Logf("Created policy %+v", policyResp.AgentPolicy)

	t.Log("Getting default Fleet Server URL...")
	fleetServerURL, err := fleettools.DefaultURL(prepareCtx, info.KibanaClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	// Get path to Elastic Agent executable
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// Prepare the Elastic Agent so the binary is extracted and ready to use.
	err = fixture.Prepare(prepareCtx)
	require.NoError(t, err)

	maxRunTime := 2 * time.Minute
	for i := 0; i < iterations(); i++ {
		successful := t.Run(fmt.Sprintf("%s-%d", t.Name(), i), func(t *testing.T) {
			ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(maxRunTime))
			defer cancel()

			// Run `elastic-agent install`.  We use `--force` to prevent interactive
			// execution.
			opts := &atesting.InstallOpts{
				Force: true,
				EnrollOpts: atesting.EnrollOpts{
					URL:             fleetServerURL,
					EnrollmentToken: enrollmentTokenResp.APIKey,
				},
			}
			out, err := fixture.Install(ctx, opts)
			if err != nil {
				t.Logf("install output: %s", out)
				require.NoErrorf(t, err, "install failed: %s", err)
			}

			// Check that Agent was installed in successfully
			require.NoError(t, installtest.CheckSuccess(ctx, fixture, opts.BasePath, &installtest.CheckOpts{Privileged: opts.Privileged}))

			// Check connected to Fleet.
			check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)

			// Perform uninstall.
			out, err = fixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
			if err != nil {
				t.Logf("uninstall output: %s", out)
				require.NoErrorf(t, err, "uninstall failed: %s", err)
			}
		})
		if !successful {
			// quit now, another test run will continue to fail now
			return
		}
	}
}

func iterations() int {
	// If running in CI, reduce the number of iterations to speed up the test.
	if os.Getenv("BUILDKITE_PULL_REQUEST") != "" {
		return 50
	}
	return 100
}

func randStr(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	runes := make([]rune, length)
	for i := range runes {
		runes[i] = letters[rand.IntN(len(letters))]
	}

	return string(runes)
}
