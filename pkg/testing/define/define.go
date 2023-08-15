// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package define

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-sysinfo"
	"github.com/elastic/go-sysinfo/types"
	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/utils"
	semver "github.com/elastic/elastic-agent/pkg/version"
	"github.com/elastic/elastic-agent/version"
)

var osInfo *types.OSInfo
var osInfoErr error
var osInfoOnce sync.Once
var noSpecialCharsRegexp = regexp.MustCompile("[^a-zA-Z0-9]+")

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

// Version returns the version of the Elastic Agent the tests should be using.
func Version() string {
	ver := os.Getenv("AGENT_VERSION")
	if ver == "" {
		return version.GetDefaultVersion()
	}
	return ver
}

// NewFixture returns a new Elastic Agent testing fixture with a LocalFetcher and
// the agent logging to the test logger.
func NewFixture(t *testing.T, version string, opts ...atesting.FixtureOpt) (*atesting.Fixture, error) {
	buildsDir := os.Getenv("AGENT_BUILD_DIR")
	if buildsDir == "" {
		projectDir, err := findProjectRoot()
		if err != nil {
			return nil, err
		}
		buildsDir = filepath.Join(projectDir, "build", "distributions")
	}

	fixture, err := NewFixtureWithBinary(t, version, "elastic-agent", buildsDir)
	require.NoError(t, err)
	return fixture, nil
}

// NewFixture returns a new Elastic Agent testing fixture with a LocalFetcher and
// the agent logging to the test logger.
func NewFixtureWithBinary(t *testing.T, version string, binary string, buildsDir string, opts ...atesting.FixtureOpt) (*atesting.Fixture, error) {
	ver, err := semver.ParseVersion(version)
	if err != nil {
		return nil, fmt.Errorf("%q is an invalid agent version: %w", version, err)
	}

	var binFetcher atesting.Fetcher
	if ver.IsSnapshot() {
		binFetcher = atesting.LocalFetcher(buildsDir, binary, atesting.WithLocalSnapshotOnly())
	} else {
		binFetcher = atesting.LocalFetcher(buildsDir, binary)
	}

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

func runOrSkip(t *testing.T, req Requirements, local bool) *Info {
	// always validate requirement is valid
	if err := req.Validate(); err != nil {
		panic(fmt.Sprintf("test %s has invalid requirements: %s", t.Name(), err))
	}
	if !req.Local && local {
		t.Skip("running local only tests and this test doesn't support local")
		return nil
	}
	if req.Sudo {
		// we can run sudo tests if we are being executed as root
		root, err := utils.HasRoot()
		if err != nil {
			panic(fmt.Sprintf("test %s failed to determine if running as root: %s", t.Name(), err))
		}
		if !root {
			t.Skip("not running as root and test requires root")
			return nil
		}
	}
	// need OS info to determine if the test can run
	osInfo, err := getOSInfo()
	if err != nil {
		panic("failed to get OS information")
	}
	if !req.runtimeAllowed(runtime.GOOS, runtime.GOARCH, osInfo.Version, osInfo.Platform) {
		t.Skip("platform, architecture, version, and distro not supported by test")
		return nil
	}
	namespace, err := getNamespace(t, local)
	if err != nil {
		panic(err)
	}
	info := &Info{
		Namespace: namespace,
	}
	if req.Stack != nil {
		info.ESClient, err = getESClient()
		if err != nil {
			if local {
				t.Skipf("test requires a stack but failed to create a valid client to elasticsearch: %s", err)
				return nil
			}
			// non-local test and stack was required
			panic(err)
		}
		info.KibanaClient, err = getKibanaClient()
		if err != nil {
			if local {
				t.Skipf("test requires a stack but failed to create a valid client to kibana: %s", err)
				return nil
			}
			// non-local test and stack was required
			panic(err)
		}
	}
	return info
}

func getOSInfo() (*types.OSInfo, error) {
	osInfoOnce.Do(func() {
		sysInfo, err := sysinfo.Host()
		if err != nil {
			osInfoErr = err
		} else {
			osInfo = sysInfo.Info().OS
		}
	})
	return osInfo, osInfoErr
}

// getNamespace is a general namespace that the test can use that will ensure that it
// is unique and won't collide with other tests (even the same test from a different batch).
//
// this function uses a sha256 of the prefix, package and test name, to ensure that the
// length of the namespace is not over the 100 byte limit from Fleet
// see: https://www.elastic.co/guide/en/fleet/current/data-streams.html#data-streams-naming-scheme
func getNamespace(t *testing.T, local bool) (string, error) {
	prefix := os.Getenv("TEST_DEFINE_PREFIX")
	if prefix == "" {
		if local {
			prefix = "local"
		}
		if prefix == "" {
			return "", errors.New("TEST_DEFINE_PREFIX must be defined by the test runner")
		}
	}
	name := fmt.Sprintf("%s-%s", prefix, t.Name())
	hasher := sha256.New()
	hasher.Write([]byte(name))

	// Fleet API requires the namespace to be lowercased and not contain
	// special characters.
	namespace := strings.ToLower(base64.URLEncoding.EncodeToString(hasher.Sum(nil)))
	namespace = noSpecialCharsRegexp.ReplaceAllString(namespace, "")

	return namespace, nil
}

// getESClient creates the elasticsearch client from the information passed from the test runner.
func getESClient() (*elasticsearch.Client, error) {
	esHost := os.Getenv("ELASTICSEARCH_HOST")
	esUser := os.Getenv("ELASTICSEARCH_USERNAME")
	esPass := os.Getenv("ELASTICSEARCH_PASSWORD")
	if esHost == "" || esUser == "" || esPass == "" {
		return nil, errors.New("ELASTICSEARCH_* must be defined by the test runner")
	}
	c, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{esHost},
		Username:  esUser,
		Password:  esPass,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create elasticsearch client: %w", err)
	}
	return c, nil
}

// getKibanaClient creates the kibana client from the information passed from the test runner.
func getKibanaClient() (*kibana.Client, error) {
	kibanaHost := os.Getenv("KIBANA_HOST")
	kibanaUser := os.Getenv("KIBANA_USERNAME")
	kibanaPass := os.Getenv("KIBANA_PASSWORD")
	if kibanaHost == "" || kibanaUser == "" || kibanaPass == "" {
		return nil, errors.New("KIBANA_* must be defined by the test runner")
	}
	c, err := kibana.NewClientWithConfigDefault(&kibana.ClientConfig{
		Host:          kibanaHost,
		Username:      kibanaUser,
		Password:      kibanaPass,
		IgnoreVersion: true,
	}, 0, "Elastic-Agent-Test-Define", version.GetDefaultVersion(), version.Commit(), version.BuildTime().String())
	if err != nil {
		return nil, fmt.Errorf("failed to create kibana client: %w", err)
	}
	return c, nil
}
