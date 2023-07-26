// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package define

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
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

	// Stack defines the stack required for this batch.
	Stack *Stack `json:"stack,omitempty"`

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
func DetermineBatches(dir string, testFlags string, buildTags ...string) ([]Batch, error) {
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
	// #nosec G204 -- test function code, it will be okay
	cmdArgs := []string{"test", "-v", "--tags", strings.Join(buildTags, ","), "-json"}
	if testFlags != "" {
		flags := strings.Split(testFlags, " ")
		cmdArgs = append(cmdArgs, flags...)
	}

	cmdArgs = append(cmdArgs, dir)
	testCmd := exec.Command("go", cmdArgs...)
	output, err := testCmd.Output()
	if err != nil {
		// format cmdArgs to make the error message more coherent
		cmdArgs = append([]string{"go"}, cmdArgs...)

		var errExit *exec.ExitError
		if errors.As(err, &errExit) {
			b := bytes.NewBuffer(errExit.Stderr)
			b.Write(output)
			output = b.Bytes()
		}
		return nil, fmt.Errorf(
			"error running go test: (%w), got:\n\n%s\ntried to run: %v",
			err, string(output), cmdArgs)
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
			batchIdx = findBatchIdx(batches, o, req.Stack)
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
		if req.Stack != nil && batch.Stack == nil {
			// assign the stack to this batch
			batch.Stack = copyStack(req.Stack)
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
			for _, testName := range pt.Tests {
				if testName == name {
					// we already selected this test for this package for this batch,
					// we can return immediately
					return tests
				}
			}
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

func findBatchIdx(batches []Batch, os OS, stack *Stack) int {
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
		if stack == nil {
			// don't care if the batch has a cloud or not
			return i
		}
		if b.Stack == nil {
			// need cloud, but batch doesn't have cloud calling code can set it
			return i
		}
		if b.Stack.Version == stack.Version {
			// same cloud version; compatible
			return i
		}
	}
	return -1
}

func copyStack(stack *Stack) *Stack {
	var s Stack
	if stack != nil {
		s = *stack
		return &s
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
