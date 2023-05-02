// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package define

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/go-elasticsearch/v8"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/version"
)

// Require defines what this test requires for it to be run by the test runner.
//
// This must be defined as the first line of a test, otherwise the test runner.
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
	ver := os.Getenv("TEST_DEFINE_AGENT_VERSION")
	if ver == "" {
		return version.GetDefaultVersion()
	}
	return ver
}

// NewFixture returns a new Elastic Agent testing fixture.
func NewFixture(t *testing.T, opts ...atesting.FixtureOpt) (*atesting.Fixture, error) {
	buildsDir := os.Getenv("TEST_DEFINE_AGENT_BUILD_DIR")
	if buildsDir == "" {
		projectDir, err := findProjectRoot()
		if err != nil {
			return nil, err
		}
		buildsDir = filepath.Join(projectDir, "build", "distributions")
	}
	f := atesting.LocalFetcher(buildsDir)
	opts = append(opts, atesting.WithFetcher(f), atesting.WithLogOutput())
	return atesting.NewFixture(t, Version(), opts...)
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
