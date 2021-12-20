// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build mage
// +build mage

package main

import (
	"fmt"
	devtools "github.com/elastic/elastic-agent-poc/dev-tools/mage"
	"github.com/elastic/elastic-agent-poc/dev-tools/mage/gotool"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"io"
	"os/exec"
	"sync"
)

// Fmt formats code and adds license headers.
func Fmt() {
	mg.Deps(devtools.GoImports, devtools.PythonAutopep8)
	mg.Deps(AddLicenseHeaders)
}

// AddLicenseHeaders adds ASL2 headers to .go files outside of x-pack and
// add Elastic headers to .go files in x-pack.
func AddLicenseHeaders() error {
	fmt.Println(">> fmt - go-licenser: Adding missing headers")

	mg.Deps(devtools.InstallGoLicenser)

	licenser := gotool.Licenser

	return multierr.Combine(
		licenser(
			licenser.Check(),
			licenser.License("ASL2"),
			licenser.Exclude("elastic-agent"),
		),
		licenser(
			licenser.License("Elastic"),
			licenser.Path("elastic-agent"),
		),
	)
}

// CheckLicenseHeaders checks ASL2 headers in .go files outside of x-pack and
// checks Elastic headers in .go files in x-pack.
func CheckLicenseHeaders() error {
	fmt.Println(">> fmt - go-licenser: Checking for missing headers")

	mg.Deps(devtools.InstallGoLicenser)

	licenser := gotool.Licenser

	return multierr.Combine(
		licenser(
			licenser.Check(),
			licenser.License("ASL2"),
			licenser.Exclude("elastic-agent"),
		),
		licenser(
			licenser.Check(),
			licenser.License("Elastic"),
			licenser.Path("elastic-agent"),
		),
	)
}

// DumpVariables writes the template variables and values to stdout.
func DumpVariables() error {
	return devtools.DumpVariables()
}

// Notice regenerates the NOTICE.txt file.
func Notice() error {
	fmt.Println(">> Generating NOTICE")
	fmt.Println(">> fmt - go mod tidy")
	err := sh.RunV("go", "mod", "tidy", "-v")
	if err!= nil {
		return errors.Wrap(err, "failed running go mod tidy, please fix the issues reported")
	}
	fmt.Println(">> fmt - go mod download")
	err = sh.RunV("go", "mod", "download")
	if err!= nil {
		return errors.Wrap(err, "failed running go mod download, please fix the issues reported")
	}
	fmt.Println(">> fmt - go list")
	str, err := sh.Output("go", "list", "-m", "-json", "all")
	if err != nil {
		return errors.Wrap(err, "failed running go list, please fix the issues reported")
	}
	fmt.Println(">> fmt - go run")
	cmd := exec.Command("go", "run", "go.elastic.co/go-licence-detector", "-includeIndirect", "-rules", "dev-tools/notice/rules.json" , "-overrides", "dev-tools/notice/overrides.json", "-noticeTemplate", "dev-tools/notice/NOTICE.txt.tmpl",
		"-noticeOut", "NOTICE.txt", "-depsOut","\"\"")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return errors.Wrap(err, "failed running go run, please fix the issues reported")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer stdin.Close()
		defer wg.Done()
		if _, err := io.WriteString(stdin, str); err != nil {
			fmt.Println(err)
		}
	}()
	wg.Wait()
	_, err = cmd.CombinedOutput()
	if err != nil {
		return errors.Wrap(err, "failed combined output, please fix the issues reported")
	}
  return nil
}


func CheckNoChanges() error {
	fmt.Println(">> fmt - go run")
	err := sh.RunV("go", "mod", "tidy", "-v")
	if err!= nil {
		return errors.Wrap(err, "failed running go mod tidy, please fix the issues reported")
	}
	fmt.Println(">> fmt - git diff")
	err = sh.RunV("git", "diff")
	if err!= nil {
		return errors.Wrap(err, "failed running git diff, please fix the issues reported")
	}
	fmt.Println(">> fmt - git update-index")
	err = sh.RunV("git", "update-index", "--refresh")
	if err!= nil {
		return errors.Wrap(err, "failed running git update-index --refresh, please fix the issues reported")
	}
	fmt.Println(">> fmt - git diff-index")
	err = sh.RunV("git", "diff-index", "--exit-code", "HEAD", " --")
	if err!= nil {
		return errors.Wrap(err, "failed running go mod tidy, please fix the issues reported")
	}
	return nil
}

