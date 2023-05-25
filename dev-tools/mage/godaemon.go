// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mage

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent/dev-tools/mage/gotool"
)

var (
	defaultCrossBuildGoDaemon = []CrossBuildOption{
		ForPlatforms("linux"),
		WithTarget("buildGoDaemon"),
	}
)

// BuildGoDaemon builds the go-deamon binary.
func BuildGoDaemon() error {
	if GOOS != "linux" {
		return errors.New("go-daemon only builds for linux")
	}

	if os.Getenv("GOLANG_CROSSBUILD") != "1" {
		return errors.New("Use the crossBuildGoDaemon target. buildGoDaemon can " +
			"only be executed within the golang-crossbuild docker environment.")
	}

	// Test if binaries are up-to-date.
	godaemonDir, err := gotool.ListModuleCacheDir("github.com/tsg/go-daemon")
	if err != nil {
		return err
	}
	input := filepath.Join(godaemonDir, "src", "god.c")
	output := MustExpand("build/golang-crossbuild/god-{{.Platform.GOOS}}-{{.Platform.Arch}}")
	if IsUpToDate(output, input) {
		log.Println(">>> buildGoDaemon is up-to-date for", Platform.Name)
		return nil
	}

	// Determine what compiler to use based on CC that is set by golang-crossbuild.
	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}

	compileCmd := []string{
		cc,
		input,
		"-o", createDir(output),
		"-lpthread", "-static",
	}
	switch Platform.Name {
	case "linux/amd64":
		compileCmd = append(compileCmd, "-m64")
	case "linux/386":
		compileCmd = append(compileCmd, "-m32")
	}

	defer DockerChown(output)
	return RunCmds(compileCmd)
}

// CrossBuildGoDaemon cross-build the go-daemon binary using the
// golang-crossbuild environment.
func CrossBuildGoDaemon(options ...CrossBuildOption) error {
	fmt.Println("--- CrossBuildGoDaemon Elastic-Agent")
	opts := append(defaultCrossBuildGoDaemon, options...)
	return CrossBuild(opts...)
}
