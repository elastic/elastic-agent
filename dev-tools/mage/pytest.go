// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mage

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// WINDOWS USERS:
// The python installer does not create a python3 alias like it does on other
// platforms. So do verify the version with python.exe --version.
//
// Setting up a python virtual environment on a network drive does not work
// well. So if this applies to your development environment set PYTHON_ENV
// to point to somewhere on C:\.

const (
	libbeatRequirements    = "{{ elastic_beats_dir}}/libbeat/tests/system/requirements.txt"
	aixLibbeatRequirements = "{{ elastic_beats_dir}}/libbeat/tests/system/requirements_aix.txt"
)

var (
	// VirtualenvReqs specifies a list of virtualenv requirements files to be
	// used when calling PythonVirtualenv(). It defaults to the libbeat
	// requirements.txt file.
	VirtualenvReqs = []string{
		libbeatRequirements,
	}

	pythonVirtualenvDir  string // Location of python virtualenv (lazily set).
	pythonVirtualenvLock sync.Mutex

	// More globs may be needed in the future if tests are added in more places.
	pythonTestFiles = []string{
		"tests/system/test_*.py",
		"module/*/test_*.py",
		"module/*/*/test_*.py",
	}

	// pythonExe points to the python executable to use. The PYTHON_EXE
	// environment can be used to modify the executable used.
	// On Windows this defaults to python and on all other platforms this
	// defaults to python3.
	pythonExe = EnvOr("PYTHON_EXE", "python3")
)

func init() {
	// The python installer for Windows does not setup a python3 alias.
	if runtime.GOOS == "windows" {
		pythonExe = EnvOr("PYTHON_EXE", "python")
	}
}

// PythonTestArgs are the arguments used for the "python*Test" targets and they
// define how python tests are invoked.
type PythonTestArgs struct {
	TestName            string            // Test name used in logging.
	Env                 map[string]string // Env vars to add to the current env.
	Files               []string          // Globs used to find tests.
	XUnitReportFile     string            // File to write the XUnit XML test report to.
	CoverageProfileFile string            // Test coverage profile file.
}

func makePythonTestArgs(name string) PythonTestArgs {
	fileName := fmt.Sprintf("build/TEST-python-%s", strings.Replace(strings.ToLower(name), " ", "_", -1))

	params := PythonTestArgs{
		TestName:        name,
		Env:             map[string]string{},
		XUnitReportFile: fileName + ".xml",
	}
	if TestCoverage {
		params.CoverageProfileFile = fileName + ".cov"
	}
	return params
}

// DefaultPythonTestUnitArgs returns a default set of arguments for running
// all unit tests.
func DefaultPythonTestUnitArgs() PythonTestArgs { return makePythonTestArgs("Unit") }

// DefaultPythonTestIntegrationArgs returns a default set of arguments for
// running all integration tests. Integration tests are made conditional by
// checking for INTEGRATION_TEST=1 in the test code.
func DefaultPythonTestIntegrationArgs() PythonTestArgs { return makePythonTestArgs("Integration") }

// PythonVirtualenv constructs a virtualenv that contains the given modules as
// defined in the requirements file pointed to by requirementsTxt. It returns
// the path to the virtualenv.
func PythonVirtualenv() (string, error) {
	pythonVirtualenvLock.Lock()
	defer pythonVirtualenvLock.Unlock()

	// Certain docker requirements simply won't build on AIX
	// Skipping them here will obviously break the components that require docker-compose,
	// But at least the components that don't require it will still run
	if runtime.GOOS == "aix" {
		VirtualenvReqs[0] = aixLibbeatRequirements
	}

	// Determine the location of the virtualenv.
	ve, err := pythonVirtualenvPath()
	if err != nil {
		return "", err
	}

	reqs := expandVirtualenvReqs()

	// Only execute if requirements.txt is newer than the virtualenv activate
	// script.
	activate := virtualenvPath(ve, "activate")
	if IsUpToDate(activate, reqs...) {
		return pythonVirtualenvDir, nil
	}

	// Create a virtual environment only if the dir does not exist.
	if _, err := os.Stat(ve); err != nil {
		if err := sh.Run(pythonExe, "-m", "venv", ve); err != nil {
			return "", err
		}
	}

	// activate sets this. Not sure if it's ever needed.
	env := map[string]string{
		"VIRTUAL_ENV": ve,
	}

	pip := virtualenvPath(ve, "pip")
	pipUpgrade := func(pkg string) error {
		return sh.RunWith(env, pip, "install", "-U", pkg)
	}

	// Ensure we are using the latest pip version.
	if err = pipUpgrade("pip"); err != nil {
		fmt.Printf("warn: failed to upgrade pip (ignoring): %v", err)
	}

	// First ensure that wheel is installed so that bdists build cleanly.
	if err = pipUpgrade("wheel"); err != nil {
		return "", err
	}

	// Execute pip to install the dependencies.
	args := []string{"install"}
	if !mg.Verbose() {
		args = append(args, "--quiet")
	}
	for _, req := range reqs {
		args = append(args, "-Ur", req)
	}
	if err := sh.RunWith(env, pip, args...); err != nil {
		return "", err
	}

	// Touch activate script.
	mtime := time.Now()
	if err := os.Chtimes(activate, mtime, mtime); err != nil {
		log.Fatal(err)
	}

	return ve, nil
}

// pythonVirtualenvPath determines the location of the Python virtualenv.
func pythonVirtualenvPath() (string, error) {
	if pythonVirtualenvDir != "" {
		return pythonVirtualenvDir, nil
	}

	// PYTHON_ENV can override the default location. This is used by CI to
	// shorten the overall shebang interpreter path below the path length limits.
	pythonVirtualenvDir = os.Getenv("PYTHON_ENV")
	if pythonVirtualenvDir == "" {
		info, err := GetProjectRepoInfo()
		if err != nil {
			return "", err
		}

		pythonVirtualenvDir = info.RootDir
	}
	pythonVirtualenvDir = filepath.Join(pythonVirtualenvDir, "build/ve")

	// Use OS and docker specific virtualenv's because the interpreter in
	// scripts is different.
	if IsInIntegTestEnv() {
		pythonVirtualenvDir = filepath.Join(pythonVirtualenvDir, "docker")
	} else {
		pythonVirtualenvDir = filepath.Join(pythonVirtualenvDir, runtime.GOOS)
	}

	return pythonVirtualenvDir, nil
}

// virtualenvPath builds the path to a binary (in the OS specific binary path).
func virtualenvPath(ve string, parts ...string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(append([]string{ve, "Scripts"}, parts...)...)
	}
	return filepath.Join(append([]string{ve, "bin"}, parts...)...)
}

// LookVirtualenvPath looks for an executable in the path and it includes the
// virtualenv in the search.
func LookVirtualenvPath(ve, file string) (string, error) {
	// This is kind of unsafe w.r.t. concurrent execs because they could end
	// up with different PATHs. But it allows us to search the VE path without
	// having to re-implement the exec.LookPath logic. And does not require us
	// to "deactivate" the virtualenv because we never activated it.
	path := os.Getenv("PATH")
	os.Setenv("PATH", virtualenvPath(ve)+string(filepath.ListSeparator)+path)
	defer os.Setenv("PATH", path)

	return exec.LookPath(file)
}

func expandVirtualenvReqs() []string {
	out := make([]string, 0, len(VirtualenvReqs))
	for _, path := range VirtualenvReqs {
		out = append(out, MustExpand(path))
	}
	return out
}
