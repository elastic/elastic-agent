// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package define

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// defaultOS is the set of OS that are used in the case that a requirement doesn't define any
var defaultOS = []OS{
	{
		Type: Darwin,
		Arch: AMD64,
	},
	{
		Type: Darwin,
		Arch: ARM64,
	},
	{
		Type: Linux,
		Arch: AMD64,
	},
	{
		Type: Linux,
		Arch: ARM64,
	},
	{
		Type: Windows,
		Arch: AMD64,
	},
}

// Batch is a grouping of tests that all have the same requirements.
type Batch struct {
	// OS defines the operating systems this test batch needs.
	OS OS `json:"os"`

	// Cloud defines the cloud instance required for this batch.
	Cloud *Cloud `json:"cloud,omitempty"`

	// Isolate defines that this batch is isolated to a single test.
	Isolate bool `json:"isolate"`

	// Tests define the set of packages and tests that do not require sudo
	// privileges to be performed.
	Tests []BatchPackageTests `json:"tests"`

	// SudoTests define the set of packages and tests that do require sudo
	// privileges to be performed.
	SudoTests []BatchPackageTests `json:"sudo_tests"`
}

// BatchPackageTests is a package and its tests that belong to a batch.
type BatchPackageTests struct {
	// Name is the package name.
	Name string `json:"name"`
	// Tests is the set of tests in the package.
	Tests []string `json:"tests"`
}

// DetermineBatches parses the package directory with the possible extra build
// tags to determine the set of batches for the package.
func DetermineBatches(dir string, buildTags ...string) ([]Batch, error) {
	const (
		defineMatcher = "define skip; requirements: "
	)

	// the 'define' build tag is added so that the `define.Require` skips and
	// logs the requirements for each test.
	buildTags = append(buildTags, "define")

	// 'go test' wants a directory path to either be absolute or start with
	// './' so it knows it's a directory and not package.
	if !filepath.IsAbs(dir) && !strings.HasPrefix(dir, "./") {
		dir = "./" + dir
	}

	// run 'go test' and collect the JSON output to be parsed
	testCmd := exec.Command("go", "test", "-v", "--tags", strings.Join(buildTags, ","), "-json", dir)
	output, err := testCmd.Output()
	if err != nil {
		return nil, err
	}

	// parses each test and determine the batches that each test belongs in
	var batches []Batch
	sc := bufio.NewScanner(bytes.NewReader(output))
	for sc.Scan() {
		var tar testActionResult
		err := json.Unmarshal([]byte(sc.Text()), &tar)
		if err != nil {
			return nil, err
		}
		if tar.Action == "output" && strings.Contains(tar.Output, defineMatcher) {
			reqRaw := tar.Output[strings.Index(tar.Output, defineMatcher)+len(defineMatcher) : strings.LastIndex(tar.Output, "\n")]
			var req Requirements
			err := json.Unmarshal([]byte(reqRaw), &req)
			if err != nil {
				return nil, fmt.Errorf("failed to parse requirements JSON from test %s/%s: %w", tar.Package, tar.Test, err)
			}
			err = req.Validate()
			if err != nil {
				return nil, fmt.Errorf("parsed requirements are invalid JSON from test %s/%s: %w", tar.Package, tar.Test, err)
			}
			batches = appendTest(batches, tar, req)
		}
	}
	return batches, nil
}

func appendTest(batches []Batch, tar testActionResult, req Requirements) []Batch {
	var set []OS
	for _, o := range req.OS {
		if o.Arch == "" {
			set = append(set, OS{
				Type:    o.Type,
				Arch:    AMD64,
				Version: o.Version,
				Distro:  o.Distro,
			})
			if o.Type != Windows {
				set = append(set, OS{
					Type:    o.Type,
					Arch:    ARM64,
					Version: o.Version,
					Distro:  o.Distro,
				})
			}
		} else {
			set = append(set, OS{
				Type:    o.Type,
				Arch:    AMD64,
				Version: o.Version,
				Distro:  o.Distro,
			})
		}
	}
	if len(set) == 0 {
		// no os define; means the test supports all
		set = defaultOS
	}
	for _, o := range set {
		var batch Batch
		batchIdx := -1
		if !req.Isolate {
			batchIdx = findBatchIdx(batches, o, req.Cloud)
		}
		if batchIdx == -1 {
			// new batch required
			batch = Batch{
				OS:        o,
				Isolate:   req.Isolate,
				Tests:     nil,
				SudoTests: nil,
			}
			batches = append(batches, batch)
			batchIdx = len(batches) - 1
		}
		batch = batches[batchIdx]
		if o.Distro != "" {
			batch.OS.Distro = o.Distro
		}
		if o.Version != "" {
			batch.OS.Version = o.Version
		}
		if req.Cloud != nil && batch.Cloud == nil {
			// assign the cloud to this batch
			batch.Cloud = copyCloud(req.Cloud)
		}
		if req.Sudo {
			batch.SudoTests = appendPackageTest(batch.SudoTests, tar.Package, tar.Test)
		} else {
			batch.Tests = appendPackageTest(batch.Tests, tar.Package, tar.Test)
		}
		batches[batchIdx] = batch
	}
	return batches
}

func appendPackageTest(tests []BatchPackageTests, pkg string, name string) []BatchPackageTests {
	for i, pt := range tests {
		if pt.Name == pkg {
			pt.Tests = append(pt.Tests, name)
			tests[i] = pt
			return tests
		}
	}
	var pt BatchPackageTests
	pt.Name = pkg
	pt.Tests = append(pt.Tests, name)
	tests = append(tests, pt)
	return tests
}

func findBatchIdx(batches []Batch, os OS, cloud *Cloud) int {
	for i, b := range batches {
		if b.Isolate {
			// never add to an isolate batch
			continue
		}
		if b.OS.Type != os.Type || b.OS.Arch != os.Arch {
			// must be same type and arch both are always defined at this point
			continue
		}
		if os.Distro != "" {
			// must have the same distro
			if b.OS.Distro != "" && b.OS.Distro != os.Distro {
				continue
			}
		}
		if os.Version != "" {
			// must have the same version
			if b.OS.Version != "" && b.OS.Version != os.Version {
				continue
			}
		}
		if cloud == nil {
			// don't care if the batch has a cloud or not
			return i
		}
		if b.Cloud == nil {
			// need cloud, but batch doesn't have cloud calling code can set it
			return i
		}
		if b.Cloud.Version == cloud.Version {
			// same cloud version; compatible
			return i
		}
	}
	return -1
}

func copyCloud(cloud *Cloud) *Cloud {
	var c Cloud
	if cloud != nil {
		c = *cloud
		return &c
	}
	return nil
}

type testActionResult struct {
	Time    string `json:"Time"`
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}
