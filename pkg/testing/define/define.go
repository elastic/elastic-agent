// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package define

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/go-elasticsearch/v8"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	semver "github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/version"

	"sigs.k8s.io/e2e-framework/klient"
)

// Require defines what this test requires for it to be run by the test runner.
//
// This must be defined as the first line of a test, or `ValidateDir` will fail
// and the test runner will not be able to determine the requirements for a test.
func Require(t *testing.T, req Requirements) *Info {
	return defineAction(t, req)
}

type Info struct {
	// ESClient is the elasticsearch client to communicate with elasticsearch.
	// This is only present if you say a cloud is required in the `define.Require`.
	ESClient *elasticsearch.Client

	// KibanaClient is the kibana client to communicate with kibana.
	// This is only present if you say a cloud is required in the `define.Require`.
	KibanaClient *kibana.Client

	// Namespace should be used for isolating data and actions per test.
	//
	// This is unique to each test and instance combination so a test that need to
	// read/write data to a data stream in elasticsearch do not collide.
	Namespace string
}

func (i *Info) KubeClient() (klient.Client, error) {
	c, err := klient.NewWithKubeConfigFile(os.Getenv("KUBECONFIG"))
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Version returns the version of the Elastic Agent the tests should be using.
func Version() string {
	ver := os.Getenv("AGENT_VERSION")
	if ver == "" {
		return version.GetDefaultVersion()
	}
	return ver
}

// NewFixtureFromLocalBuild returns a new Elastic Agent testing fixture with a LocalFetcher and
// the agent logging to the test logger.
func NewFixtureFromLocalBuild(t *testing.T, version string, opts ...atesting.FixtureOpt) (*atesting.Fixture, error) {
	return NewFixtureWithBinary(t, version, "elastic-agent", buildsDir(t), false, opts...)
}

// NewFixtureFromLocalFIPSBuild returns a new FIPS-capable Elastic Agent testing fixture with a LocalFetcher
// and the agent logging to the test logger.
func NewFixtureFromLocalFIPSBuild(t *testing.T, version string, opts ...atesting.FixtureOpt) (*atesting.Fixture, error) {
	return NewFixtureWithBinary(t, version, "elastic-agent", buildsDir(t), true, opts...)
}

// NewFixtureWithBinary returns a new Elastic Agent testing fixture with a LocalFetcher and
// the agent logging to the test logger.
func NewFixtureWithBinary(t *testing.T, version string, binary string, buildsDir string, fips bool, opts ...atesting.FixtureOpt) (*atesting.Fixture, error) {
	ver, err := semver.ParseVersion(version)
	if err != nil {
		return nil, fmt.Errorf("%q is an invalid agent version: %w", version, err)
	}

	localFetcherOpts := []atesting.LocalFetcherOpt{atesting.WithCustomBinaryName(binary)}
	if ver.IsSnapshot() {
		localFetcherOpts = append(localFetcherOpts, atesting.WithLocalSnapshotOnly())
	}
	if fips {
		localFetcherOpts = append(localFetcherOpts, atesting.WithLocalFIPSOnly())
	}
	binFetcher := atesting.LocalFetcher(buildsDir, localFetcherOpts...)

	opts = append(opts, atesting.WithFetcher(binFetcher), atesting.WithLogOutput())
	if binary != "elastic-agent" {
		opts = append(opts, atesting.WithBinaryName(binary))
	}
	return atesting.NewFixture(t, version, opts...)
}

// findProjectRoot finds the root directory of the project, by finding the go.mod file.
func findProjectRoot() (string, error) {
	_, caller, _, ok := runtime.Caller(1)
	if !ok {
		return "", errors.New("unable to determine callers file path")
	}

	dir := caller
	for {
		dir = filepath.Dir(dir)
		fi, err := os.Stat(filepath.Join(dir, "go.mod"))
		if (err == nil || os.IsExist(err)) && !fi.IsDir() {
			return dir, nil
		}
		if strings.HasSuffix(dir, string(filepath.Separator)) {
			// made it to root directory
			return "", fmt.Errorf("unable to find golang root directory from caller path %s", caller)
		}
	}
}

func buildsDir(t *testing.T) string {
	t.Helper()

	buildsDir := os.Getenv("AGENT_BUILD_DIR")
	if buildsDir == "" {
		projectDir, err := findProjectRoot()
		require.NoError(t, err)
		buildsDir = filepath.Join(projectDir, "build", "distributions")
	}

	return buildsDir
}
