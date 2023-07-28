// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package paths

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/elastic/elastic-agent/internal/pkg/release"
)

const (
	// DefaultConfigName is the default name of the configuration file.
	DefaultConfigName = "elastic-agent.yml"
	// AgentLockFileName is the name of the overall Elastic Agent file lock.
	AgentLockFileName = "agent.lock"
	tempSubdir        = "tmp"
	tempSubdirPerms   = 0o770

	darwin = "darwin"
)

// ExternalInputsPattern is a glob that matches the paths of external configuration files.
var ExternalInputsPattern = filepath.Join("inputs.d", "*.yml")

var (
	topPath         string
	configPath      string
	configFilePath  string
	logsPath        string
	downloadsPath   string
	componentsPath  string
	installPath     string
	unversionedHome bool
	tmpCreator      sync.Once
)

func init() {
	topPath = initialTop()
	configPath = topPath
	logsPath = topPath
	unversionedHome = false // only versioned by container subcommand

	// these should never change
	versionedHome := VersionedHome(topPath)
	downloadsPath = filepath.Join(versionedHome, "downloads")
	componentsPath = filepath.Join(versionedHome, "components")

	fs := flag.CommandLine
	fs.StringVar(&topPath, "path.home", topPath, "Agent root path")
	fs.BoolVar(&unversionedHome, "path.home.unversioned", unversionedHome, "Agent root path is not versioned based on build")
	fs.StringVar(&configPath, "path.config", configPath, "Config path is the directory Agent looks for its config file")
	fs.StringVar(&configFilePath, "c", DefaultConfigName, "Configuration file, relative to path.config")
	fs.StringVar(&logsPath, "path.logs", logsPath, "Logs path contains Agent log output")
	fs.StringVar(&installPath, "path.install", installPath, "Install path contains binaries Agent extracts")

	// enable user to download update artifacts to alternative place
	// TODO: remove path.downloads support on next major (this can be configured using `agent.download.targetDirectory`)
	// `path.download` serves just as init value for `agent.download.targetDirectory`
	fs.StringVar(&downloadsPath, "path.downloads", downloadsPath, "Downloads path contains binaries Agent downloads")
}

// Top returns the top directory for Elastic Agent, all the versioned
// home directories live under this top-level/data/elastic-agent-${hash}
func Top() string {
	return topPath
}

// SetTop overrides the Top path.
//
// Used by the container subcommand to adjust the overall top path allowing state can be maintained between container
// restarts.
func SetTop(path string) {
	topPath = path
}

// TempDir returns agent temp dir located within data dir.
func TempDir() string {
	tmpDir := filepath.Join(Data(), tempSubdir)
	tmpCreator.Do(func() {
		// create tempdir as it probably don't exists
		_ = os.MkdirAll(tmpDir, tempSubdirPerms)
	})
	return tmpDir
}

// Home returns a directory where binary lives
func Home() string {
	if unversionedHome {
		return topPath
	}
	return VersionedHome(topPath)
}

// IsVersionHome returns true if the Home path is versioned based on build.
func IsVersionHome() bool {
	return !unversionedHome
}

// SetVersionHome sets if the Home path is versioned based on build.
//
// Used by the container subcommand to adjust the home path allowing state can be maintained between container
// restarts.
func SetVersionHome(version bool) {
	unversionedHome = !version
}

// Config returns a directory where configuration file lives
func Config() string {
	return configPath
}

// SetConfig overrides the Config path.
//
// Used by the container subcommand to adjust the overall config path allowing state can be maintained between container
// restarts.
func SetConfig(path string) {
	configPath = path
}

// ConfigFile returns the path to the configuration file.
func ConfigFile() string {
	if configFilePath == "" || configFilePath == DefaultConfigName {
		return filepath.Join(Config(), DefaultConfigName)
	}
	if filepath.IsAbs(configFilePath) {
		return configFilePath
	}
	return filepath.Join(Config(), configFilePath)
}

// ExternalInputs returns the path to load external inputs from.
func ExternalInputs() string {
	return filepath.Join(Config(), ExternalInputsPattern)
}

// Data returns the data directory for Agent
func Data() string {
	if unversionedHome {
		// unversioned means the topPath is the data path
		return topPath
	}
	return filepath.Join(Top(), "data")
}

// Run returns the run directory for Agent
func Run() string {
	return filepath.Join(Home(), "run")
}

// Components returns the component directory for Agent
func Components() string {
	return componentsPath
}

// Logs returns the log directory for Agent
func Logs() string {
	return logsPath
}

// SetLogs updates the path for the logs.
func SetLogs(path string) {
	logsPath = path
}

// VersionedHome returns a versioned path based on a TopPath and used commit.
func VersionedHome(base string) string {
	return filepath.Join(base, "data", fmt.Sprintf("elastic-agent-%s", release.ShortCommit()))
}

// Downloads returns the downloads directory for Agent
func Downloads() string {
	return downloadsPath
}

// SetDownloads updates the path for the downloads.
func SetDownloads(path string) {
	downloadsPath = path
}

// Install returns the install directory for Agent
func Install() string {
	if installPath == "" {
		return filepath.Join(Home(), "install")
	}
	return installPath
}

// SetInstall updates the path for the install.
func SetInstall(path string) {
	installPath = path
}

// initialTop returns the initial top-level path for the binary
//
// When nested in top-level/data/elastic-agent-${hash}/ the result is top-level/.
// The agent executable for MacOS is wrapped in the app bundle, so the path to the binary is
// top-level/data/elastic-agent-${hash}/elastic-agent.app/Contents/MacOS
func initialTop() string {
	return ExecDir(retrieveExecutableDir())
}

// retrieveExecutablePath returns the executing binary, even if the started binary was a symlink
func retrieveExecutableDir() string {
	execPath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	evalPath, err := filepath.EvalSymlinks(execPath)
	if err != nil {
		panic(err)
	}
	return filepath.Dir(evalPath)
}

// isInsideData returns true when the exePath is inside of the current Agents data path.
func isInsideData(exeDir string) bool {
	expectedDir := binaryDir(filepath.Join("data", fmt.Sprintf("elastic-agent-%s", release.ShortCommit())))
	return strings.HasSuffix(exeDir, expectedDir)
}

// ExecDir returns the "executable" directory which is:
// 1. The same if the execDir is not inside of the data path
// 2. Two levels up if the execDir inside of the data path on non-macOS platforms
// 3. Five levels up if the execDir inside of the dataPath on macOS platform
func ExecDir(execDir string) string {
	if isInsideData(execDir) {
		execDir = filepath.Dir(filepath.Dir(execDir))
		if runtime.GOOS == darwin {
			execDir = filepath.Dir(filepath.Dir(filepath.Dir(execDir)))
		}
	}
	return execDir
}

// binaryDir returns the application binary directory
// For macOS it appends the path inside of the app bundle
// For other platforms it returns the same dir
func binaryDir(baseDir string) string {
	if runtime.GOOS == darwin {
		baseDir = filepath.Join(baseDir, "elastic-agent.app", "Contents", "MacOS")
	}
	return baseDir
}

// BinaryPath returns the application binary path that is concatenation of the directory and the agentName
func BinaryPath(baseDir, agentName string) string {
	return filepath.Join(binaryDir(baseDir), agentName)
}

// InstallPath returns the top level directory Agent will be installed into.
func InstallPath(basePath string) string {
	return filepath.Join(basePath, "Elastic", "Agent")
}

// TopBinaryPath returns the path to the Elastic Agent binary that is inside the Top directory.
//
// This always points to the symlink that points to the latest Elastic Agent version.
func TopBinaryPath() string {
	return BinaryPath(Top(), BinaryName)
}
