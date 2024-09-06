// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgradetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/elastic/elastic-agent/testing/installtest"

	"github.com/hectane/go-acl"
	"github.com/otiai10/copy"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	v1client "github.com/elastic/elastic-agent/pkg/control/v1/client"
	v2proto "github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/version"
)

// CustomPGP allows for custom PGP options on upgrade.
type CustomPGP struct {
	PGP     string
	PGPUri  string
	PGPPath string
}

type upgradeOpts struct {
	sourceURI *string

	unprivileged     *bool
	skipVerify       bool
	skipDefaultPgp   bool
	customPgp        *CustomPGP
	customWatcherCfg string

	// Used to disable upgrade details checks for versions that don't support them, like 7.17.x.
	// See also WithDisableUpgradeWatcherUpgradeDetailsCheck.
	disableUpgradeWatcherUpgradeDetailsCheck bool

	// Disable check that enforces different hashed between the to and from version of upgrade
	disableHashCheck bool

	preInstallHook  func() error
	postInstallHook func() error
	preUpgradeHook  func() error
	postUpgradeHook func() error
}

type UpgradeOpt func(opts *upgradeOpts)

// WithSourceURI sets a specific --source-uri for the upgrade
// command. This doesn't change the verification of the upgrade
// the resulting upgrade must still be the same agent provided
// in the endFixture variable.
func WithSourceURI(sourceURI string) UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.sourceURI = &sourceURI
	}
}

// WithUnprivileged sets the install to be explicitly unprivileged.
func WithUnprivileged(unprivileged bool) UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.unprivileged = &unprivileged
	}
}

// WithSkipVerify sets the skip verify option for upgrade.
func WithSkipVerify(skipVerify bool) UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.skipVerify = skipVerify
	}
}

// WithSkipDefaultPgp sets the skip default pgp option for upgrade.
func WithSkipDefaultPgp(skipDefaultPgp bool) UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.skipDefaultPgp = skipDefaultPgp
	}
}

// WithCustomPGP sets a custom pgp configuration for upgrade.
func WithCustomPGP(customPgp CustomPGP) UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.customPgp = &customPgp
	}
}

// WithPreInstallHook sets a hook to be called before install.
func WithPreInstallHook(hook func() error) UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.preInstallHook = hook
	}
}

// WithPostInstallHook sets a hook to be called before install.
func WithPostInstallHook(hook func() error) UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.postInstallHook = hook
	}
}

// WithPreUpgradeHook sets a hook to be called before install.
func WithPreUpgradeHook(hook func() error) UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.preUpgradeHook = hook
	}
}

// WithPostUpgradeHook sets a hook to be called before install.
func WithPostUpgradeHook(hook func() error) UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.postUpgradeHook = hook
	}
}

// WithCustomWatcherConfig sets a custom watcher configuration to use.
func WithCustomWatcherConfig(cfg string) UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.customWatcherCfg = cfg
	}
}

// WithDisableUpgradeWatcherUpgradeDetailsCheck disables any assertions for
// upgrade details that are being set by the Upgrade Watcher. This option is
// useful in upgrade tests where the end Agent version does not contain changes
// in the Upgrade Watcher whose effects are being asserted upon in PerformUpgrade.
func WithDisableUpgradeWatcherUpgradeDetailsCheck() UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.disableUpgradeWatcherUpgradeDetailsCheck = true
	}
}

// WithDisableHashCheck disables hash check between start and end versions of upgrade
func WithDisableHashCheck(disable bool) UpgradeOpt {
	return func(opts *upgradeOpts) {
		opts.disableHashCheck = disable
	}
}

// PerformUpgrade performs the upgrading of the Elastic Agent.
func PerformUpgrade(
	ctx context.Context,
	startFixture *atesting.Fixture,
	endFixture *atesting.Fixture,
	logger Logger,
	opts ...UpgradeOpt,
) error {
	// use the passed in options to perform the upgrade
	// `skipVerify` is by default enabled, because default is to perform a local
	// upgrade to a built version of the Elastic Agent.
	var upgradeOpts upgradeOpts
	upgradeOpts.skipVerify = true
	for _, o := range opts {
		o(&upgradeOpts)
	}

	// ensure that both the starting and ending fixtures are prepared
	err := startFixture.EnsurePrepared(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare the startFixture: %w", err)
	}
	err = endFixture.EnsurePrepared(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare the endFixture: %w", err)
	}

	// start fixture gets the agent configured to use a faster watcher
	if upgradeOpts.customWatcherCfg != "" {
		err = startFixture.Configure(ctx, []byte(upgradeOpts.customWatcherCfg))
	} else {
		err = ConfigureFastWatcher(ctx, startFixture)
	}
	if err != nil {
		return fmt.Errorf("failed configuring the start agent with faster watcher configuration: %w", err)
	}

	// get the versions from each fixture (that ensures that it's always the
	// same version that the fixture is working with)
	startVersionInfo, err := startFixture.ExecVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get start agent build version info: %w", err)
	}
	startParsedVersion, err := version.ParseVersion(startVersionInfo.Binary.String())
	if err != nil {
		return fmt.Errorf("failed to get parsed start agent build version (%s): %w", startVersionInfo.Binary.String(), err)
	}
	startVersion, err := version.ParseVersion(startVersionInfo.Binary.Version)
	if err != nil {
		return fmt.Errorf("failed to parse version of starting Agent binary: %w", err)
	}
	endVersionInfo, err := endFixture.ExecVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get end agent build version info: %w", err)
	}
	endVersion, err := version.ParseVersion(endVersionInfo.Binary.Version)
	if err != nil {
		return fmt.Errorf("failed to parse version of upgraded Agent binary: %w", err)
	}

	// in the unprivileged is unset we adjust it to use unprivileged when the version allows it
	// in the case that its explicitly set then we ensure the version supports it
	if upgradeOpts.unprivileged == nil {
		if SupportsUnprivileged(startVersion, endVersion) {
			unprivileged := true
			upgradeOpts.unprivileged = &unprivileged
			logger.Logf("installation of Elastic Agent will use --unprivileged as both start and end version support --unprivileged mode")
		} else {
			// must be privileged
			unprivileged := false
			upgradeOpts.unprivileged = &unprivileged
		}
	} else if *upgradeOpts.unprivileged {
		if !SupportsUnprivileged(startVersion, endVersion) {
			return fmt.Errorf("cannot install with forced --unprivileged because either start version %s or end version %s doesn't support --unprivileged mode", startVersion.String(), endVersion.String())
		}
	}

	if !upgradeOpts.disableHashCheck && startVersionInfo.Binary.Commit == endVersionInfo.Binary.Commit {
		return fmt.Errorf("target version has the same commit hash %q", endVersionInfo.Binary.Commit)
	}

	// For asserting on the effects of any Upgrade Watcher changes made in 8.12.0, we need
	// the endVersion to be >= 8.12.0.  Otherwise, these assertions will fail as those changes
	// won't be present in the Upgrade Watcher. So we disable these assertions if the endVersion
	// is < 8.12.0.
	//
	// The start version also needs to be >= 8.10.0. Versions before 8.10.0 will launch the watcher
	// process from the starting version of the agent and not the ending version of the agent. So
	// even though an 8.12.0 watcher knows to write the upgrade details, prior to 8.10.0 the 8.12.0
	// watcher version never executes and the upgrade details are never populated.
	upgradeOpts.disableUpgradeWatcherUpgradeDetailsCheck = upgradeOpts.disableUpgradeWatcherUpgradeDetailsCheck ||
		endVersion.Less(*version.NewParsedSemVer(8, 12, 0, "", "")) ||
		startParsedVersion.Less(*version.NewParsedSemVer(8, 10, 0, "", ""))

	if upgradeOpts.preInstallHook != nil {
		if err := upgradeOpts.preInstallHook(); err != nil {
			return fmt.Errorf("pre install hook failed: %w", err)
		}
	}

	logger.Logf("Installing version %q", startParsedVersion.VersionWithPrerelease())

	// install the start agent
	var nonInteractiveFlag bool
	if Version_8_2_0.Less(*startParsedVersion) {
		nonInteractiveFlag = true
	}
	installOpts := atesting.InstallOpts{
		NonInteractive: nonInteractiveFlag,
		Force:          true,
		Privileged:     !(*upgradeOpts.unprivileged),
	}
	output, err := startFixture.Install(ctx, &installOpts)
	if err != nil {
		return fmt.Errorf("failed to install start agent (err: %w) [output: %s]", err, string(output))
	}

	if upgradeOpts.postInstallHook != nil {
		if err := upgradeOpts.postInstallHook(); err != nil {
			return fmt.Errorf("post install hook failed: %w", err)
		}
	}

	// wait for the agent to be healthy and correct version
	err = WaitHealthyAndVersion(ctx, startFixture, startVersionInfo.Binary, 2*time.Minute, 10*time.Second, logger)
	if err != nil {
		// context added by WaitHealthyAndVersion
		return err
	}

	// validate installation is correct
	if InstallChecksAllowed(!installOpts.Privileged, startVersion) {
		err = installtest.CheckSuccess(ctx, startFixture, installOpts.BasePath, &installtest.CheckOpts{Privileged: installOpts.Privileged})
		if err != nil {
			return fmt.Errorf("pre-upgrade installation checks failed: %w", err)
		}
	}

	if upgradeOpts.preUpgradeHook != nil {
		if err := upgradeOpts.preUpgradeHook(); err != nil {
			return fmt.Errorf("pre upgrade hook failed: %w", err)
		}
	}

	logger.Logf("Upgrading from version \"%s-%s\" to version \"%s-%s\"", startParsedVersion, startVersionInfo.Binary.Commit, endVersionInfo.Binary.String(), endVersionInfo.Binary.Commit)

	upgradeCmdArgs := []string{"upgrade", endVersionInfo.Binary.String()}
	if upgradeOpts.sourceURI == nil {
		// no --source-uri set so it comes from the endFixture
		sourceURI, err := getSourceURI(ctx, endFixture, *upgradeOpts.unprivileged)
		if err != nil {
			return fmt.Errorf("failed to get end agent source package path: %w", err)
		}
		upgradeCmdArgs = append(upgradeCmdArgs, "--source-uri", sourceURI)
	} else if *upgradeOpts.sourceURI != "" {
		// specific --source-uri
		upgradeCmdArgs = append(upgradeCmdArgs, "--source-uri", *upgradeOpts.sourceURI)
	}

	if upgradeOpts.customPgp != nil {
		if len(upgradeOpts.customPgp.PGP) > 0 {
			upgradeCmdArgs = append(upgradeCmdArgs, "--pgp", upgradeOpts.customPgp.PGP)
		}

		if len(upgradeOpts.customPgp.PGPUri) > 0 {
			upgradeCmdArgs = append(upgradeCmdArgs, "--pgp-uri", upgradeOpts.customPgp.PGPUri)
		}

		if len(upgradeOpts.customPgp.PGPPath) > 0 {
			upgradeCmdArgs = append(upgradeCmdArgs, "--pgp-path", upgradeOpts.customPgp.PGPPath)
		}
	}

	if upgradeOpts.skipVerify {
		upgradeCmdArgs = append(upgradeCmdArgs, "--skip-verify")
	}

	if upgradeOpts.skipDefaultPgp && !startParsedVersion.Less(*Version_8_10_0_SNAPSHOT) {
		upgradeCmdArgs = append(upgradeCmdArgs, "--skip-default-pgp")
	}

	upgradeOutput, err := startFixture.Exec(ctx, upgradeCmdArgs)
	if err != nil {
		// Sometimes the gRPC server shuts down before replying to the command which is expected
		// we can determine this state by the EOF error coming from the server.
		// If the server is just unavailable/not running, we should not succeed.
		// Starting with version 8.13.2, this is handled by the upgrade command itself.
		outputString := string(upgradeOutput)
		isConnectionInterrupted := strings.Contains(outputString, "Unavailable") && strings.Contains(outputString, "EOF")
		if !isConnectionInterrupted {
			return fmt.Errorf("failed to start agent upgrade to version %q: %w\n%s", endVersionInfo.Binary.Version, err, upgradeOutput)
		}
	}

	// wait for the watcher to show up
	logger.Logf("waiting for upgrade watcher to start")
	err = WaitForWatcher(ctx, 5*time.Minute, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to find watcher: %w", err)
	}
	logger.Logf("upgrade watcher started")

	// Check that, while the Upgrade Watcher is running, the upgrade details in Agent status
	// show the state as UPG_WATCHING.
	if !upgradeOpts.disableUpgradeWatcherUpgradeDetailsCheck {
		logger.Logf("Checking upgrade details state while Upgrade Watcher is running")
		if err := waitUpgradeDetailsState(ctx, startFixture, details.StateWatching, 2*time.Minute, 10*time.Second, logger); err != nil {
			// error context added by waitUpgradeDetailsState
			return err
		}
	}

	if upgradeOpts.postUpgradeHook != nil {
		if err := upgradeOpts.postUpgradeHook(); err != nil {
			return fmt.Errorf("post upgrade hook failed: %w", err)
		}
	}

	// wait for the agent to be healthy and correct version
	err = WaitHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary, 2*time.Minute, 10*time.Second, logger)
	if err != nil {
		// agent never got healthy, but we need to ensure the watcher is stopped before continuing
		// this kills the watcher instantly and waits for it to be gone before continuing
		watcherErr := WaitForNoWatcher(ctx, 1*time.Minute, time.Second, 100*time.Millisecond)
		if watcherErr != nil {
			logger.Logf("failed to kill watcher due to agent not becoming healthy: %s", watcherErr)
		}

		// error context added by WaitHealthyAndVersion
		return err
	}

	// it is unstable to continue until the watcher is done
	// the maximum wait time is 10 minutes (12 minutes for grace) some older versions
	// do not respect the `ConfigureFastWatcher` so we have to kill the watcher after the
	// 10 minute window (10 min 15 seconds for grace) has passed.
	logger.Logf("waiting for upgrade watcher to finish")
	err = WaitForNoWatcher(ctx, 12*time.Minute, 10*time.Second, 10*time.Minute+15*time.Second)
	if err != nil {
		return fmt.Errorf("watcher never stopped running: %w", err)
	}
	logger.Logf("upgrade watcher finished")

	// Check that, upon successful upgrade, the upgrade details have been cleared out
	// from Agent status.
	if !upgradeOpts.disableUpgradeWatcherUpgradeDetailsCheck {
		logger.Logf("Checking upgrade details state after successful upgrade")
		if err := waitUpgradeDetailsState(ctx, startFixture, "", 2*time.Minute, 10*time.Second, logger); err != nil {
			// error context added by checkUpgradeDetailsState
			return err
		}
	}

	// now that the watcher has stopped lets ensure that it's still the expected
	// version, otherwise it's possible that it was rolled back to the original version
	err = CheckHealthyAndVersion(ctx, startFixture, endVersionInfo.Binary)
	if err != nil {
		// error context added by CheckHealthyAndVersion
		return err
	}

	// validate again that the installation is correct, upgrade should not have changed installation validation
	if InstallChecksAllowed(!installOpts.Privileged, startVersion, endVersion) {
		err = installtest.CheckSuccess(ctx, startFixture, installOpts.BasePath, &installtest.CheckOpts{Privileged: installOpts.Privileged})
		if err != nil {
			return fmt.Errorf("post-upgrade installation checks failed: %w", err)
		}
	}

	return nil
}

var ErrVerMismatch = errors.New("versions don't match")

func CheckHealthyAndVersion(ctx context.Context, f *atesting.Fixture, versionInfo atesting.AgentBinaryVersion) error {
	checkFunc := func() error {
		status, err := f.ExecStatus(ctx)
		if err != nil {
			return err
		}
		if status.Info.Version != versionInfo.Version {
			return fmt.Errorf("%w: got %s, want %s",
				ErrVerMismatch,
				status.Info.Version, versionInfo.Version)
		}
		if status.Info.Snapshot != versionInfo.Snapshot {
			return fmt.Errorf("snapshots don't match: got %t, want %t",
				status.Info.Snapshot, versionInfo.Snapshot)
		}
		if status.Info.Commit != versionInfo.Commit {
			return fmt.Errorf("commits don't match: got %s, want %s",
				status.Info.Commit, versionInfo.Commit)
		}
		if status.State != int(v2proto.State_HEALTHY) {
			return fmt.Errorf("agent state is not healthy: got %d",
				status.State)
		}
		return nil
	}

	parsedVersion, err := version.ParseVersion(versionInfo.Version)
	if err != nil {
		return fmt.Errorf("failed to get parsed version (%s): %w", versionInfo.Version, err)
	}
	if parsedVersion.Less(*Version_8_6_0) {
		// we have to handle v1 architecture of the Elastic Agent
		checkFunc = func() error {
			stateOut, err := f.Exec(ctx, []string{"status", "--output", "json"})
			if err != nil {
				return err
			}
			var state v1client.AgentStatus
			err = json.Unmarshal(stateOut, &state)
			if err != nil {
				return err
			}
			versionOut, err := f.ExecVersion(ctx)
			if err != nil {
				return err
			}

			if versionOut.Binary.Version != versionInfo.Version {
				return fmt.Errorf("versions don't match: got %s, want %s",
					versionOut.Binary.Version, versionInfo.Version)
			}
			if versionOut.Binary.Snapshot != versionInfo.Snapshot {
				return fmt.Errorf("snapshots don't match: got %t, want %t",
					versionOut.Binary.Snapshot, versionInfo.Snapshot)
			}
			if versionOut.Binary.Commit != versionInfo.Commit {
				return fmt.Errorf("commits don't match: got %s, want %s",
					versionOut.Binary.Commit, versionInfo.Commit)
			}
			if state.Status != v1client.Healthy {
				return fmt.Errorf("agent state is not healthy: got %d",
					state.Status)
			}
			return nil
		}
	}

	return checkFunc()
}

func WaitHealthyAndVersion(ctx context.Context, f *atesting.Fixture, versionInfo atesting.AgentBinaryVersion, timeout time.Duration, interval time.Duration, logger Logger) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The deadline was set above, we don't need to check for it.
	deadline, _ := ctx.Deadline()

	t := time.NewTicker(interval)
	defer t.Stop()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("failed waiting for healthy agent and version (%w): %w", ctx.Err(), lastErr)
			}
			return ctx.Err()
		case <-t.C:
			err := CheckHealthyAndVersion(ctx, f, versionInfo)
			// If we're in an upgrade process, the versions might not match
			// so we wait to see if we get to a stable version
			if errors.Is(err, ErrVerMismatch) {
				logger.Logf("version mismatch, ignoring it, time until timeout: %s", deadline.Sub(time.Now()))
				continue
			}
			if err == nil {
				return nil
			}
			lastErr = err
			logger.Logf("waiting for healthy agent and proper version: %s", err)
		}
	}
}

func waitUpgradeDetailsState(ctx context.Context, f *atesting.Fixture, expectedState details.State, timeout time.Duration, interval time.Duration, logger Logger) error {
	versionStr, err := f.ExecVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Agent version: %w", err)
	}

	versionParsed, err := version.ParseVersion(versionStr.Binary.Version)
	if err != nil {
		return fmt.Errorf("failed to parse version [%s]: %w", versionStr.Binary.Version, err)
	}

	// Upgrade details are only available in Agent version >= 8.12.0
	versionUpgradeDetailsAvailable := version.NewParsedSemVer(8, 12, 0, "", "")
	if versionParsed.Less(*versionUpgradeDetailsAvailable) {
		logger.Logf("upgrade details functionality not implemented in Agent version [%s]. Skipping check for upgrade details state.", versionParsed.String())
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t := time.NewTicker(interval)
	defer t.Stop()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("failed waiting for status: %w", errors.Join(ctx.Err(), lastErr))
			}
			return ctx.Err()
		case <-t.C:
			status, err := f.ExecStatus(ctx)
			if err != nil && status.IsZero() {
				lastErr = err
				continue
			}

			if expectedState == "" {
				if status.UpgradeDetails == nil {
					// Expected and actual match, so we're good
					return nil
				}

				lastErr = errors.New("upgrade details found in status but they were expected to be absent")
				continue
			}

			if status.UpgradeDetails == nil {
				lastErr = fmt.Errorf("upgrade details not found in status but expected upgrade details state was [%s]", expectedState)
				continue
			}

			// Neither expected nor actual are nil, so compare the two
			if status.UpgradeDetails.State == expectedState {
				return nil
			}

			lastErr = fmt.Errorf("upgrade details state in status [%s] is not the same as expected upgrade details state  [%s]", status.UpgradeDetails.State, expectedState)
			continue
		}
	}
}

func getSourceURI(ctx context.Context, f *atesting.Fixture, unprivileged bool) (string, error) {
	srcPkg, err := f.SrcPackage(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get source package: %w", err)
	}
	if unprivileged {
		// move the file to temp directory
		baseTmp := ""
		if runtime.GOOS == "windows" {
			// `elastic-agent-user` needs to have access to the file, default
			// will place this in C:\Users\windows\AppData\Local\Temp\ which
			// `elastic-agent-user` doesn't have access.

			// create C:\Temp with world read/write to use for temp directory
			baseTmp, err = windowsBaseTemp()
			if err != nil {
				return "", fmt.Errorf("failed to create windows base temp path: %w", err)
			}
		}
		dir, err := os.MkdirTemp(baseTmp, "agent-upgrade-*")
		if err != nil {
			return "", fmt.Errorf("failed to create temp directory: %w", err)
		}
		err = os.Chmod(dir, 0777)
		if err != nil {
			return "", fmt.Errorf("failed to chmod temp directory: %w", err)
		}
		for _, suffix := range []string{"", ".sha512"} {
			source := fmt.Sprintf("%s%s", srcPkg, suffix)
			dest := fmt.Sprintf("%s%s", filepath.Join(dir, filepath.Base(srcPkg)), suffix)
			err = copy.Copy(source, dest, copy.Options{
				PermissionControl: copy.AddPermission(0777),
			})
			if err != nil {
				return "", fmt.Errorf("failed to copy %s -> %s: %w", source, dest, err)
			}
		}
		srcPkg = filepath.Join(dir, filepath.Base(srcPkg))
	}
	return "file://" + filepath.Dir(srcPkg), nil
}

func windowsBaseTemp() (string, error) {
	baseTmp := "C:\\Temp"
	_, err := os.Stat(baseTmp)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("failed to stat %s: %w", baseTmp, err)
		}
		err = os.Mkdir(baseTmp, 0777)
		if err != nil {
			return "", fmt.Errorf("failed to mkdir %s: %w", baseTmp, err)
		}
	}
	err = acl.Chmod(baseTmp, 0777)
	if err != nil {
		return "", fmt.Errorf("failed to chmod %s: %w", baseTmp, err)
	}
	return baseTmp, nil
}
