// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"context"
	"errors"
	"fmt"
	"go/build"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/magefile/mage/sh"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/dev-tools/mage/gotool"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
)

const (
	fpmVersion = "1.13.1"

	// Docker images. See https://github.com/elastic/golang-crossbuild.
	beatsFPMImage = "docker.elastic.co/beats-dev/fpm"
	// BeatsCrossBuildImage is the image used for crossbuilding Beats.
	BeatsCrossBuildImage = "docker.elastic.co/beats-dev/golang-crossbuild"

	elasticAgentImportPath = "github.com/elastic/elastic-agent"

	elasticAgentModulePath = "github.com/elastic/elastic-agent"

	//ManifestUrlEnvVar is the name fo the environment variable containing the Manifest URL to be used for packaging agent
	ManifestUrlEnvVar = "MANIFEST_URL"
	// AgentCommitHashEnvVar allows to override agent commit hash string during packaging

	// Mapped functions
	agentPackageVersionMappedFunc    = "agent_package_version"
	agentManifestGeneratorMappedFunc = "manifest"
	snapshotSuffix                   = "snapshot_suffix"
	SnapshotSuffix                   = "-SNAPSHOT"

	// Default beat settings.
	DefaultName        = "elastic-agent"
	DefaultDescription = "Elastic Agent - single, unified way to add monitoring for logs, metrics, and other types of data to a host."
	DefaultLicense     = "Elastic License 2.0"
	DefaultVendor      = "Elastic"
	DefaultUser        = "root"

	// DefaultDevMachineImage is the default GCP machine image for dev machines.
	DefaultDevMachineImage = "family/platform-ingest-elastic-agent-ubuntu-2204"
	// DefaultDevMachineZone is the default GCP zone for dev machines.
	DefaultDevMachineZone = "us-central1-a"
)

// XPackDir is the directory containing x-pack code (relative path constant).
const XPackDir = "../x-pack"

// BeatProjectType specifies the type of project (OSS vs X-Pack).
var BeatProjectType ProjectType

// FuncMap returns template functions that use the config.
func FuncMap(cfg *Settings) map[string]interface{} {
	return map[string]interface{}{
		"beat_doc_branch":                func() (string, error) { return BeatDocBranchFromConfig(cfg) },
		"beat_version":                   func() (string, error) { return BeatQualifiedVersion(cfg) },
		"commit":                         func() (string, error) { return cfg.Build.CommitHash() },
		"commit_short":                   func() (string, error) { return cfg.Build.CommitHashShort() },
		"date":                           BuildDate,
		"elastic_beats_dir":              ElasticBeatsDir,
		"go_version":                     func() (string, error) { return GoVersion(cfg) },
		"repo":                           GetProjectRepoInfo,
		"title":                          func(s string) string { return cases.Title(language.English, cases.NoLower).String(s) },
		"tolower":                        strings.ToLower,
		"contains":                       strings.Contains,
		"substring":                      Substring,
		agentPackageVersionMappedFunc:    func() (string, error) { return AgentPackageVersion(cfg) },
		agentManifestGeneratorMappedFunc: func(fips bool) (string, error) { return PackageManifest(cfg, fips) },
		snapshotSuffix:                   func() string { return MaybeSnapshotSuffix(cfg) },
	}
}

// ProjectType specifies the type of project (OSS vs X-Pack).
type ProjectType uint8

// Project types.
const (
	OSSProject ProjectType = iota
	XPackProject
	CommunityProject
)

// ErrUnknownProjectType is returned if an unknown ProjectType value is used.
var ErrUnknownProjectType = fmt.Errorf("unknown ProjectType")

// EnvMap returns map containing the common settings variables and all variables
// from the environment. args are appended to the output prior to adding the
// environment variables (so env vars have the highest precedence).
func EnvMap(cfg *Settings, args ...map[string]interface{}) map[string]interface{} {
	envMap := varMap(cfg, args...)

	// Add the environment (highest precedence).
	for _, e := range os.Environ() {
		env := strings.SplitN(e, "=", 2)
		envMap[env[0]] = env[1]
	}

	return envMap
}

func varMap(cfg *Settings, args ...map[string]interface{}) map[string]interface{} {
	data := map[string]interface{}{
		"GOOS":            cfg.Build.GOOS,
		"GOARCH":          cfg.Build.GOARCH,
		"GOARM":           cfg.Build.GOARM,
		"Platform":        cfg.Platform(),
		"PLATFORMS":       cfg.CrossBuild.Platforms,
		"PACKAGES":        cfg.CrossBuild.Packages,
		"BinaryExt":       cfg.BinaryExt(),
		"XPackDir":        XPackDir,
		"BeatName":        cfg.Beat.Name,
		"BeatServiceName": cfg.Beat.ServiceName,
		"BeatIndexPrefix": cfg.Beat.IndexPrefix,
		"BeatDescription": cfg.Beat.Description,
		"BeatVendor":      cfg.Beat.Vendor,
		"BeatLicense":     cfg.Beat.License,
		"BeatURL":         cfg.Beat.URL,
		"BeatUser":        cfg.Beat.User,
		"Snapshot":        cfg.Build.Snapshot,
		"DEV":             cfg.Build.DevBuild,
		"EXTERNAL":        cfg.Build.ExternalBuild,
		"FIPS":            cfg.Build.FIPSBuild,
		"Qualifier":       cfg.Build.VersionQualifier,
		"CI":              cfg.Build.CI,
	}

	// Add the extra args to the map.
	for _, m := range args {
		for k, v := range m {
			data[k] = v
		}
	}

	return data
}

func dumpVariables(cfg *Settings) (string, error) {
	var dumpTemplate = `## Variables

GOOS             = {{.GOOS}}
GOARCH           = {{.GOARCH}}
GOARM            = {{.GOARM}}
Platform         = {{.Platform}}
BinaryExt        = {{.BinaryExt}}
XPackDir         = {{.XPackDir}}
BeatName         = {{.BeatName}}
BeatServiceName  = {{.BeatServiceName}}
BeatIndexPrefix  = {{.BeatIndexPrefix}}
BeatDescription  = {{.BeatDescription}}
BeatVendor       = {{.BeatVendor}}
BeatLicense      = {{.BeatLicense}}
BeatURL          = {{.BeatURL}}
BeatUser         = {{.BeatUser}}
VersionQualifier = {{.Qualifier}}
PLATFORMS        = {{.PLATFORMS}}
PACKAGES         = {{.PACKAGES}}
CI               = {{.CI}}

## Functions

beat_doc_branch              = {{ beat_doc_branch }}
beat_version                 = {{ beat_version }}
commit                       = {{ commit }}
date                         = {{ date }}
elastic_beats_dir            = {{ elastic_beats_dir }}
go_version                   = {{ go_version }}
repo.RootImportPath          = {{ repo.RootImportPath }}
repo.CanonicalRootImportPath = {{ repo.CanonicalRootImportPath }}
repo.RootDir                 = {{ repo.RootDir }}
repo.ImportPath              = {{ repo.ImportPath }}
repo.SubDir                  = {{ repo.SubDir }}
agent_package_version        = {{ agent_package_version}}
snapshot_suffix              = {{ snapshot_suffix }}
`

	return Expand(cfg, dumpTemplate)
}

// DumpVariables writes the template variables and values to stdout.
func DumpVariables(cfg *Settings) error {
	out, err := dumpVariables(cfg)
	if err != nil {
		return err
	}

	fmt.Println(out)
	return nil
}

// AgentPackageVersion returns the agent package version using the provided config.
func AgentPackageVersion(cfg *Settings) (string, error) {
	if cfg.Packaging.AgentPackageVersion != "" {
		return cfg.Packaging.AgentPackageVersion, nil
	}

	return BeatQualifiedVersion(cfg)
}

// PackageManifest generates the package manifest using the provided config.
func PackageManifest(cfg *Settings, fips bool) (string, error) {
	packageVersion, err := AgentPackageVersion(cfg)
	if err != nil {
		return "", fmt.Errorf("retrieving agent package version: %w", err)
	}

	hash, err := cfg.Build.CommitHash()
	if err != nil {
		return "", fmt.Errorf("retrieving agent commit hash: %w", err)
	}

	commitHashShort, err := cfg.Build.CommitHashShort()
	if err != nil {
		return "", fmt.Errorf("retrieving agent commit hash: %w", err)
	}

	registry, err := loadFlavorsRegistry()
	if err != nil {
		return "", fmt.Errorf("retrieving agent flavors: %w", err)
	}

	return GeneratePackageManifest(cfg.Beat.Name, packageVersion, cfg.Build.Snapshot, hash, commitHashShort, fips, registry)
}

func GeneratePackageManifest(beatName, packageVersion string, snapshot bool, fullHash, shortHash string, fips bool, flavorsRegistry map[string][]string) (string, error) {
	m := v1.NewManifest()
	m.Package.Version = packageVersion
	m.Package.Snapshot = snapshot
	m.Package.Hash = fullHash
	m.Package.Fips = fips

	versionedHomePath := path.Join("data", fmt.Sprintf("%s-%s", beatName, shortHash))
	m.Package.VersionedHome = versionedHomePath
	m.Package.PathMappings = []map[string]string{{}}
	m.Package.PathMappings[0][versionedHomePath] = fmt.Sprintf("data/%s-%s%s-%s", beatName, m.Package.Version, GenerateSnapshotSuffix(snapshot), shortHash)
	m.Package.PathMappings[0][v1.ManifestFileName] = fmt.Sprintf("data/%s-%s%s-%s/%s", beatName, m.Package.Version, GenerateSnapshotSuffix(snapshot), shortHash, v1.ManifestFileName)
	m.Package.Flavors = flavorsRegistry
	yamlBytes, err := yaml.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("marshaling manifest: %w", err)

	}
	return string(yamlBytes), nil
}

// MaybeSnapshotSuffix returns the snapshot suffix for the artifact version, or an empty string if the build isn't a
// snapshot.
func MaybeSnapshotSuffix(cfg *Settings) string {
	return GenerateSnapshotSuffix(cfg.Build.Snapshot)
}

func Substring(s string, start, length int) string {
	if start < 0 || start >= len(s) {
		return ""
	}
	end := start + length
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

func GenerateSnapshotSuffix(snapshot bool) string {
	if !snapshot {
		return ""
	}

	return SnapshotSuffix
}

var (
	elasticBeatsDirValue string
	elasticBeatsDirErr   error
	elasticBeatsDirLock  sync.Mutex
)

// SetElasticBeatsDir sets the internal elastic beats dir to a preassigned value
func SetElasticBeatsDir(path string) {
	elasticBeatsDirLock.Lock()
	defer elasticBeatsDirLock.Unlock()

	elasticBeatsDirValue = path
}

// ElasticBeatsDir returns the path to Elastic beats dir.
func ElasticBeatsDir() (string, error) {
	elasticBeatsDirLock.Lock()
	defer elasticBeatsDirLock.Unlock()

	if elasticBeatsDirValue != "" || elasticBeatsDirErr != nil {
		return elasticBeatsDirValue, elasticBeatsDirErr
	}

	elasticBeatsDirValue, elasticBeatsDirErr = findElasticBeatsDir()
	if elasticBeatsDirErr == nil {
		log.Println("Found Elastic Beats dir at", elasticBeatsDirValue)
	}
	return elasticBeatsDirValue, elasticBeatsDirErr
}

// findElasticBeatsDir returns the root directory of the Elastic Beats module, using "go list".
//
// When running within the Elastic Beats repo, this will return the repo root. Otherwise,
// it will return the root directory of the module from within the module cache or vendor
// directory.
func findElasticBeatsDir() (string, error) {
	repo, err := GetProjectRepoInfo()
	if err != nil {
		return "", err
	}
	if repo.IsElasticBeats() {
		return repo.RootDir, nil
	}
	return gotool.ListModuleCacheDir(elasticAgentModulePath)
}

var (
	buildDate = time.Now().UTC().Format(time.RFC3339)
)

// BuildDate returns the time that the build started.
func BuildDate() string {
	return buildDate
}

var (
	goVersionValue string
	goVersionErr   error
	goVersionOnce  sync.Once
)

// GoVersion returns the version of Go using the provided config.
// If BeatGoVersion is set in the config, it returns that value.
// Otherwise falls back to reading from the .go-version file.
func GoVersion(cfg *Settings) (string, error) {
	if cfg.Build.BeatGoVersion != "" {
		return cfg.Build.BeatGoVersion, nil
	}

	goVersionOnce.Do(func() {
		goVersionValue, goVersionErr = getBuildVariableSources().GetGoVersion()
	})

	return goVersionValue, goVersionErr
}

var (
	beatVersionRegex = regexp.MustCompile(`(?m)^const defaultBeatVersion = "(.+)"\r?$`)

	flavorsRegistry    map[string][]string
	flavorsRegistryErr error
	flavorsOnce        sync.Once
)

// BeatQualifiedVersion returns the Beat's qualified version using the provided config.
// This variant does not use caching, making it suitable for contexts where
// different configs may be passed.
func BeatQualifiedVersion(cfg *Settings) (string, error) {
	version, err := BeatVersion(cfg)
	if err != nil {
		return "", err
	}
	// version qualifier can intentionally be set to "" to override build time var
	if !cfg.Build.VersionQualified || cfg.Build.VersionQualifier == "" {
		return version, nil
	}
	return version + "-" + cfg.Build.VersionQualifier, nil
}

// BeatVersion returns the Beat's version using the provided config.
// This variant does not use caching, making it suitable for contexts where
// different configs may be passed.
func BeatVersion(cfg *Settings) (string, error) {
	// Check config first for BeatVersion override
	if cfg.Build.BeatVersion != "" {
		return cfg.Build.BeatVersion, nil
	}
	return getBuildVariableSources().GetBeatVersion()
}

func loadFlavorsRegistry() (map[string][]string, error) {
	flavorsOnce.Do(func() {
		flavorsRegistry, flavorsRegistryErr = getBuildVariableSources().GetFlavorsRegistry()
	})

	return flavorsRegistry, flavorsRegistryErr
}

var (
	beatDocBranchRegex     = regexp.MustCompile(`(?m)doc-branch:\s*([^\s]+)\r?$`)
	beatDocSiteBranchRegex = regexp.MustCompile(`(?m)doc-site-branch:\s*([^\s]+)\r?$`)
	beatDocBranchValue     string
	beatDocBranchErr       error
	beatDocBranchOnce      sync.Once
)

// BeatDocBranch returns the documentation branch name associated with the
// Beat branch.
// Deprecated: Use BeatDocBranchFromConfig instead.
func BeatDocBranch() (string, error) {
	beatDocBranchOnce.Do(func() {
		beatDocBranchValue, beatDocBranchErr = getBuildVariableSources().GetDocBranch()
	})

	return beatDocBranchValue, beatDocBranchErr
}

// BeatDocBranchFromConfig returns the documentation branch using the provided config.
// If BeatDocBranch is set in the config, it returns that value.
// Otherwise falls back to reading from the doc branch file.
func BeatDocBranchFromConfig(cfg *Settings) (string, error) {
	if cfg.Build.BeatDocBranch != "" {
		return cfg.Build.BeatDocBranch, nil
	}
	return BeatDocBranch()
}

// --- BuildVariableSources

var (
	// DefaultBeatBuildVariableSources contains the default locations build
	// variables are read from by Elastic Beats.
	DefaultBeatBuildVariableSources = &BuildVariableSources{
		BeatVersion:     "{{ elastic_beats_dir }}/version/version.go",
		GoVersion:       "{{ elastic_beats_dir }}/.go-version",
		DocBranch:       "{{ elastic_beats_dir }}/version/docs/version.asciidoc",
		FlavorsRegistry: "{{ elastic_beats_dir }}/_meta/.flavors",
	}

	buildVariableSources     *BuildVariableSources
	buildVariableSourcesLock sync.Mutex
)

// SetBuildVariableSources sets the BuildVariableSources that defines where
// certain build data should be sourced from. Community Beats must call this.
func SetBuildVariableSources(s *BuildVariableSources) {
	buildVariableSourcesLock.Lock()
	defer buildVariableSourcesLock.Unlock()

	buildVariableSources = s
}

func getBuildVariableSources() *BuildVariableSources {
	buildVariableSourcesLock.Lock()
	defer buildVariableSourcesLock.Unlock()

	if buildVariableSources != nil {
		return buildVariableSources
	}

	repo, err := GetProjectRepoInfo()
	if err != nil {
		panic(err)
	}
	if repo.IsElasticBeats() {
		buildVariableSources = DefaultBeatBuildVariableSources
		return buildVariableSources
	}

	panic(fmt.Errorf("magefile must call devtools.SetBuildVariableSources() "+
		"because it is not an elastic beat (repo=%+v)", repo.RootImportPath))
}

// BuildVariableSources is used to explicitly define what files contain build
// variables and how to parse the values from that file. This removes ambiguity
// about where the data is sources and allows a degree of customization for
// community Beats.
//
// Default parsers are used if one is not defined.
type BuildVariableSources struct {
	// File containing the Beat version.
	BeatVersion string

	// Parses the Beat version from the BeatVersion file.
	BeatVersionParser func(data []byte) (string, error)

	// File containing the Go version to be used in cross-builds.
	GoVersion string

	// Parses the Go version from the GoVersion file.
	GoVersionParser func(data []byte) (string, error)

	// File containing the documentation branch.
	DocBranch string

	// Parses the documentation branch from the DocBranch file.
	DocBranchParser func(data []byte) (string, error)

	// File containing definition of flavors.
	FlavorsRegistry string
}

func (s *BuildVariableSources) expandVar(in string) (string, error) {
	return expandTemplate("inline", in, map[string]interface{}{
		"elastic_beats_dir": ElasticBeatsDir,
	})
}

// GetBeatVersion reads the BeatVersion file and parses the version from it.
func (s *BuildVariableSources) GetBeatVersion() (string, error) {
	file, err := s.expandVar(s.BeatVersion)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read beat version file=%v: %w", file, err)
	}

	if s.BeatVersionParser == nil {
		s.BeatVersionParser = parseBeatVersion
	}
	return s.BeatVersionParser(data)
}

// GetGoVersion reads the GoVersion file and parses the version from it.
func (s *BuildVariableSources) GetGoVersion() (string, error) {
	file, err := s.expandVar(s.GoVersion)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read go version file=%v: %w", file, err)
	}

	if s.GoVersionParser == nil {
		s.GoVersionParser = parseGoVersion
	}
	return s.GoVersionParser(data)
}

// GetFlavorsRegistry reads the flavors file and parses the list of components of it.
func (s *BuildVariableSources) GetFlavorsRegistry() (map[string][]string, error) {
	file, err := s.expandVar(s.FlavorsRegistry)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read flavors from file=%v: %w", file, err)
	}

	registry := make(map[string][]string)
	if err := yaml.Unmarshal(data, registry); err != nil {
		return nil, fmt.Errorf("failed to parse flavors: %w", err)
	}

	return registry, nil
}

// GetDocBranch reads the DocBranch file and parses the branch from it.
func (s *BuildVariableSources) GetDocBranch() (string, error) {
	file, err := s.expandVar(s.DocBranch)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read doc branch file=%v: %w", file, err)
	}

	if s.DocBranchParser == nil {
		s.DocBranchParser = parseDocBranch
	}
	return s.DocBranchParser(data)
}

func parseBeatVersion(data []byte) (string, error) {
	matches := beatVersionRegex.FindSubmatch(data)
	if len(matches) == 2 {
		return string(matches[1]), nil
	}

	return "", errors.New("failed to parse beat version file")
}

func parseGoVersion(data []byte) (string, error) {
	return strings.TrimSpace(string(data)), nil
}

func parseDocBranch(data []byte) (string, error) {
	matches := beatDocSiteBranchRegex.FindSubmatch(data)
	if len(matches) == 2 {
		return string(matches[1]), nil
	}

	matches = beatDocBranchRegex.FindSubmatch(data)
	if len(matches) == 2 {
		return string(matches[1]), nil
	}

	return "", errors.New("failed to parse beat doc branch")
}

// --- ProjectRepoInfo

// ProjectRepoInfo contains information about the project's repo.
type ProjectRepoInfo struct {
	RootImportPath          string // Import path at the project root.
	CanonicalRootImportPath string // Pre-modules root import path (does not contain semantic import version identifier).
	RootDir                 string // Root directory of the project.
	ImportPath              string // Import path of the current directory.
	SubDir                  string // Relative path from the root dir to the current dir.
}

// IsElasticBeats returns true if the current project is
// github.com/elastic/beats.
func (r *ProjectRepoInfo) IsElasticBeats() bool {
	return r.CanonicalRootImportPath == elasticAgentImportPath
}

var (
	repoInfoValue *ProjectRepoInfo
	repoInfoErr   error
	repoInfoOnce  sync.Once
)

// GetProjectRepoInfo returns information about the repo including the root
// import path and the current directory's import path.
func GetProjectRepoInfo() (*ProjectRepoInfo, error) {
	repoInfoOnce.Do(func() {
		if isUnderGOPATH() {
			repoInfoValue, repoInfoErr = getProjectRepoInfoUnderGopath()
		} else {
			repoInfoValue, repoInfoErr = getProjectRepoInfoWithModules()
		}
	})

	return repoInfoValue, repoInfoErr
}

func isUnderGOPATH() bool {
	underGOPATH := false
	srcDirs, err := listSrcGOPATHs()
	if err != nil {
		return false
	}
	for _, srcDir := range srcDirs {
		rel, err := filepath.Rel(srcDir, CWD())
		if err != nil {
			continue
		}

		if !strings.Contains(rel, "..") {
			underGOPATH = true
		}
	}

	return underGOPATH
}

func getProjectRepoInfoWithModules() (*ProjectRepoInfo, error) {
	var (
		cwd     = CWD()
		rootDir string
		subDir  string
	)

	possibleRoot := cwd
	var errs []string
	for {
		isRoot, err := isGoModRoot(possibleRoot)
		if err != nil {
			errs = append(errs, err.Error())
		}

		if isRoot {
			rootDir = possibleRoot
			subDir, err = filepath.Rel(rootDir, cwd)
			if err != nil {
				errs = append(errs, err.Error())
			}
			break
		}

		possibleRoot = filepath.Dir(possibleRoot)
	}

	if rootDir == "" {
		return nil, fmt.Errorf("failed to find root dir of module file: %v", errs)
	}

	rootImportPath, err := gotool.GetModuleName()
	if err != nil {
		return nil, err
	}

	return &ProjectRepoInfo{
		RootImportPath:          rootImportPath,
		CanonicalRootImportPath: filepath.ToSlash(extractCanonicalRootImportPath(rootImportPath)),
		RootDir:                 rootDir,
		SubDir:                  subDir,
		ImportPath:              filepath.ToSlash(filepath.Join(rootImportPath, subDir)),
	}, nil
}

func isGoModRoot(path string) (bool, error) {
	gomodPath := filepath.Join(path, "go.mod")
	_, err := os.Stat(gomodPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func getProjectRepoInfoUnderGopath() (*ProjectRepoInfo, error) {
	var (
		cwd     = CWD()
		errs    []string
		rootDir string
	)

	srcDirs, err := listSrcGOPATHs()
	if err != nil {
		return nil, err
	}

	for _, srcDir := range srcDirs {
		root, err := fromDir(cwd, srcDir)
		if err != nil {
			// Try the next gopath.
			errs = append(errs, err.Error())
			continue
		}
		rootDir = filepath.Join(srcDir, root)
		break
	}

	if rootDir == "" {
		return nil, fmt.Errorf("error while determining root directory: %v", errs)
	}

	subDir, err := filepath.Rel(rootDir, cwd)
	if err != nil {
		err = errors.Unwrap(err)
		return nil, fmt.Errorf("failed to get relative path to repo root: %w", err)
	}

	rootImportPath, err := gotool.GetModuleName()
	if err != nil {
		return nil, err
	}

	return &ProjectRepoInfo{
		RootImportPath:          rootImportPath,
		CanonicalRootImportPath: filepath.ToSlash(extractCanonicalRootImportPath(rootImportPath)),
		RootDir:                 rootDir,
		SubDir:                  subDir,
		ImportPath:              filepath.ToSlash(filepath.Join(rootImportPath, subDir)),
	}, nil
}

var vcsList = []string{
	"hg",
	"git",
	"svn",
	"bzr",
}

func fromDir(dir, srcRoot string) (root string, err error) {
	// Clean and double-check that dir is in (a subdirectory of) srcRoot.
	dir = filepath.Clean(dir)
	srcRoot = filepath.Clean(srcRoot)
	if len(dir) <= len(srcRoot) || dir[len(srcRoot)] != filepath.Separator {
		return "", fmt.Errorf("directory %q is outside source root %q", dir, srcRoot)
	}

	var vcsRet string
	var rootRet string

	origDir := dir
	for len(dir) > len(srcRoot) {
		for _, vcs := range vcsList {
			if _, err := os.Stat(filepath.Join(dir, "."+vcs)); err == nil {
				root := filepath.ToSlash(dir[len(srcRoot)+1:])
				// Record first VCS we find, but keep looking,
				// to detect mistakes like one kind of VCS inside another.
				if vcsRet == "" {
					vcsRet = vcs
					rootRet = root
					continue
				}
				// Allow .git inside .git, which can arise due to submodules.
				if vcsRet == vcs && vcs == "git" {
					continue
				}
				// Otherwise, we have one VCS inside a different VCS.
				return "", fmt.Errorf("directory %q uses %s, but parent %q uses %s",
					filepath.Join(srcRoot, rootRet), vcsRet, filepath.Join(srcRoot, root), vcs)
			}
		}

		// Move to parent.
		ndir := filepath.Dir(dir)
		if len(ndir) >= len(dir) {
			// Shouldn't happen, but just in case, stop.
			break
		}
		dir = ndir
	}

	if vcsRet != "" {
		return rootRet, nil
	}

	return "", fmt.Errorf("directory %q is not using a known version control system", origDir)
}

func extractCanonicalRootImportPath(rootImportPath string) string {
	// In order to be compatible with go modules, the root import
	// path of any module at major version v2 or higher must include
	// the major version.
	// Ref: https://github.com/golang/go/wiki/Modules#semantic-import-versioning
	//
	// Thus, Beats has to include the major version as well.
	// This regex removes the major version from the import path.
	re := regexp.MustCompile(`(/v[1-9][0-9]*)$`)
	return re.ReplaceAllString(rootImportPath, "")
}

func listSrcGOPATHs() ([]string, error) {
	var (
		cwd     = CWD()
		errs    []string
		srcDirs []string
	)
	for _, gopath := range filepath.SplitList(build.Default.GOPATH) {
		gopath = filepath.Clean(gopath)

		if !strings.HasPrefix(cwd, gopath) {
			// Fixes an issue on macOS when /var is actually /private/var.
			var err error
			gopath, err = filepath.EvalSymlinks(gopath)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
		}

		srcDirs = append(srcDirs, filepath.Join(gopath, "src"))
	}

	if len(srcDirs) == 0 {
		return srcDirs, fmt.Errorf("failed to find any GOPATH %v", errs)
	}

	return srcDirs, nil
}

// --- Settings (formerly EnvConfig) ---

// settingsContextKey is the key used to store Settings in context.
type settingsContextKey struct{}

// SettingsFromContext returns the Settings from the context if present,
// otherwise loads fresh settings from environment variables. This is the preferred
// way to get settings in mage targets that receive a context.
func SettingsFromContext(ctx context.Context) *Settings {
	if s, ok := ctx.Value(settingsContextKey{}).(*Settings); ok && s != nil {
		return s
	}
	return MustLoadSettings()
}

// ContextWithSettings returns a new context with the given Settings stored in it.
// Use this to pass settings to dependent mage targets via mg.CtxDeps.
func ContextWithSettings(ctx context.Context, s *Settings) context.Context {
	return context.WithValue(ctx, settingsContextKey{}, s)
}

// Settings holds all settings read from environment variables.
// Use LoadSettings() or MustLoadSettings() to create a new instance, or
// SettingsFromContext() to get settings from a context.
type Settings struct {
	// Build settings
	Build BuildSettings

	// Beat metadata settings
	Beat BeatSettings

	// Test settings
	Test TestSettings

	// CrossBuild settings
	CrossBuild CrossBuildSettings

	// Packaging settings
	Packaging PackagingSettings

	// IntegrationTest settings
	IntegrationTest IntegrationTestSettings

	// Docker settings
	Docker DockerSettings

	// Kubernetes settings
	Kubernetes KubernetesSettings

	// DevMachine settings
	DevMachine DevMachineSettings

	// Fmt settings
	Fmt FmtSettings

	// PlatformFilters holds additional platform filters to apply.
	// These are applied after the base platform list is determined.
	PlatformFilters []string

	// SelectedPackageTypes overrides the package types from PACKAGES env var.
	// If nil, the env var value is used.
	SelectedPackageTypes []PackageType

	// SelectedDockerVariants overrides the docker variants from DOCKER_VARIANTS env var.
	// If nil, the env var value is used.
	SelectedDockerVariants []DockerVariant
}

// DefaultSettings returns a new Settings instance with all default values.
// It does not read from environment variables - use LoadSettings() for that.
// This is useful for tests that need settings without environment influence.
func DefaultSettings() *Settings {
	s := &Settings{}
	s.setDefaults()
	return s
}

// setDefaults sets all default values for the settings.
// This is called by NewSettings() and should not read from environment variables.
func (s *Settings) setDefaults() {
	s.setBuildDefaults()
	s.setBeatDefaults()
	s.setTestDefaults()
	s.setCrossBuildDefaults()
	s.setPackagingDefaults()
	s.setIntegrationTestDefaults()
	s.setDockerDefaults()
	s.setKubernetesDefaults()
	s.setDevMachineDefaults()
	s.setFmtDefaults()
}

// setBuildDefaults sets default values for BuildSettings.
func (s *Settings) setBuildDefaults() {
	s.Build.GOOS = build.Default.GOOS
	s.Build.GOARCH = build.Default.GOARCH
	s.Build.MaxParallel = runtime.NumCPU()
}

// setBeatDefaults sets default values for BeatSettings.
func (s *Settings) setBeatDefaults() {
	s.Beat.Name = DefaultName
	s.Beat.ServiceName = DefaultName
	s.Beat.IndexPrefix = DefaultName
	s.Beat.Description = DefaultDescription
	s.Beat.Vendor = DefaultVendor
	s.Beat.License = DefaultLicense
	s.Beat.URL = "https://www.elastic.co/beats/" + DefaultName
	s.Beat.User = DefaultUser
}

// setTestDefaults sets default values for TestSettings.
// Currently no non-zero defaults.
func (s *Settings) setTestDefaults() {
	// No non-zero defaults
}

// setCrossBuildDefaults sets default values for CrossBuildSettings.
func (s *Settings) setCrossBuildDefaults() {
	s.CrossBuild.MountModcache = true
	s.CrossBuild.MountBuildCache = true
	s.CrossBuild.BuildCacheVolumeName = "elastic-agent-crossbuild-build-cache"
	s.CrossBuild.DevOS = "linux"
	s.CrossBuild.DevArch = "amd64"
}

// setPackagingDefaults sets default values for PackagingSettings.
// Currently no non-zero defaults.
func (s *Settings) setPackagingDefaults() {
	// No non-zero defaults
}

// setIntegrationTestDefaults sets default values for IntegrationTestSettings.
func (s *Settings) setIntegrationTestDefaults() {
	s.IntegrationTest.CleanOnExit = true
	s.IntegrationTest.TestEnvironmentEnabled = true
}

// setDockerDefaults sets default values for DockerSettings.
// Currently no non-zero defaults.
func (s *Settings) setDockerDefaults() {
	// No non-zero defaults
}

// setKubernetesDefaults sets default values for KubernetesSettings.
// Currently no non-zero defaults.
func (s *Settings) setKubernetesDefaults() {
	// No non-zero defaults
}

// setDevMachineDefaults sets default values for DevMachineSettings.
func (s *Settings) setDevMachineDefaults() {
	s.DevMachine.MachineImage = DefaultDevMachineImage
	s.DevMachine.Zone = DefaultDevMachineZone
}

// setFmtDefaults sets default values for FmtSettings.
// Currently no non-zero defaults.
func (s *Settings) setFmtDefaults() {
	// No non-zero defaults
}

// Clone returns a deep copy of the Settings.
// Use this when you need to modify settings without affecting other users.
func (s *Settings) Clone() *Settings {
	clone := *s
	// Deep copy slices
	if s.Test.Tags != nil {
		clone.Test.Tags = make([]string, len(s.Test.Tags))
		copy(clone.Test.Tags, s.Test.Tags)
	}
	if s.PlatformFilters != nil {
		clone.PlatformFilters = make([]string, len(s.PlatformFilters))
		copy(clone.PlatformFilters, s.PlatformFilters)
	}
	if s.SelectedPackageTypes != nil {
		clone.SelectedPackageTypes = make([]PackageType, len(s.SelectedPackageTypes))
		copy(clone.SelectedPackageTypes, s.SelectedPackageTypes)
	}
	if s.SelectedDockerVariants != nil {
		clone.SelectedDockerVariants = make([]DockerVariant, len(s.SelectedDockerVariants))
		copy(clone.SelectedDockerVariants, s.SelectedDockerVariants)
	}
	return &clone
}

// WithDevBuild returns a copy of the settings with DevBuild set to the given value.
func (s *Settings) WithDevBuild(enabled bool) *Settings {
	clone := s.Clone()
	clone.Build.DevBuild = enabled
	return clone
}

// WithExternalBuild returns a copy of the settings with ExternalBuild set to the given value.
func (s *Settings) WithExternalBuild(enabled bool) *Settings {
	clone := s.Clone()
	clone.Build.ExternalBuild = enabled
	return clone
}

// WithFIPSBuild returns a copy of the settings with FIPSBuild set to the given value.
func (s *Settings) WithFIPSBuild(enabled bool) *Settings {
	clone := s.Clone()
	clone.Build.FIPSBuild = enabled
	return clone
}

// WithSnapshot returns a copy of the settings with Snapshot set to the given value.
func (s *Settings) WithSnapshot(enabled bool) *Settings {
	clone := s.Clone()
	clone.Build.Snapshot = enabled
	return clone
}

// WithPlatformFilter returns a copy of the settings with an additional platform filter.
func (s *Settings) WithPlatformFilter(filter string) *Settings {
	clone := s.Clone()
	clone.PlatformFilters = append(clone.PlatformFilters, filter)
	return clone
}

// WithPackageTypes returns a copy of the settings with the specified package types.
func (s *Settings) WithPackageTypes(types []PackageType) *Settings {
	clone := s.Clone()
	clone.SelectedPackageTypes = types
	return clone
}

// WithDockerVariants returns a copy of the settings with the specified docker variants.
func (s *Settings) WithDockerVariants(variants []DockerVariant) *Settings {
	clone := s.Clone()
	clone.SelectedDockerVariants = variants
	return clone
}

// WithPlatforms returns a copy of the settings with the specified platforms string.
// This replaces any existing platform configuration.
func (s *Settings) WithPlatforms(platforms string) *Settings {
	clone := s.Clone()
	clone.CrossBuild.Platforms = platforms
	clone.PlatformFilters = nil // Clear filters when setting platforms explicitly
	return clone
}

// WithAddedPackageType returns a copy of the settings with the specified package type added.
// If the package type is already selected, returns a clone with no changes.
func (s *Settings) WithAddedPackageType(pkgType PackageType) *Settings {
	clone := s.Clone()
	currentTypes := s.GetPackageTypes()
	for _, t := range currentTypes {
		if t == pkgType {
			return clone // already selected
		}
	}
	clone.SelectedPackageTypes = append(currentTypes, pkgType)
	return clone
}

// WithBeatVersion returns a copy of the settings with the specified beat version.
func (s *Settings) WithBeatVersion(version string) *Settings {
	clone := s.Clone()
	clone.Build.BeatVersion = version
	return clone
}

// WithAgentCommitHashOverride returns a copy of the settings with the specified commit hash override.
func (s *Settings) WithAgentCommitHashOverride(hash string) *Settings {
	clone := s.Clone()
	clone.Build.AgentCommitHashOverride = hash
	return clone
}

// WithAgentDropPath returns a copy of the settings with the specified agent drop path.
func (s *Settings) WithAgentDropPath(path string) *Settings {
	clone := s.Clone()
	clone.Packaging.AgentDropPath = path
	return clone
}

// WithStackProvisioner returns a copy of the settings with the specified stack provisioner.
func (s *Settings) WithStackProvisioner(provisioner string) *Settings {
	clone := s.Clone()
	clone.IntegrationTest.StackProvisioner = provisioner
	return clone
}

// WithTestGroups returns a copy of the settings with the specified test groups.
func (s *Settings) WithTestGroups(groups string) *Settings {
	clone := s.Clone()
	clone.IntegrationTest.Groups = groups
	return clone
}

// WithAgentBuildDir returns a copy of the settings with the specified agent build directory.
func (s *Settings) WithAgentBuildDir(path string) *Settings {
	clone := s.Clone()
	clone.IntegrationTest.AgentBuildDir = path
	return clone
}

// WithTestBinaryName returns a copy of the settings with the specified test binary name.
func (s *Settings) WithTestBinaryName(name string) *Settings {
	clone := s.Clone()
	clone.IntegrationTest.BinaryName = name
	return clone
}

// BuildSettings contains build-related settings.
type BuildSettings struct {
	// GOOS is the target operating system (from build.Default.GOOS)
	GOOS string

	// GOARCH is the target architecture (from build.Default.GOARCH)
	GOARCH string

	// GOARM is the ARM version for compilation (from GOARM env var)
	GOARM string

	// Snapshot indicates whether this is a snapshot build (from SNAPSHOT env var)
	Snapshot bool

	// SnapshotSet indicates whether SNAPSHOT env var was explicitly set.
	// This is needed to distinguish "not set" from "explicitly set to false"
	// in contexts where the default varies (e.g., cloud images default to true).
	// TODO: consider refactoring to use *bool or restructuring context-specific defaults.
	SnapshotSet bool

	// DevBuild indicates whether this is a development build (from DEV env var)
	DevBuild bool

	// ExternalBuild indicates whether to use external artifact builds (from EXTERNAL env var)
	ExternalBuild bool

	// ExternalBuildSet indicates whether EXTERNAL env var was explicitly set.
	// This is needed to distinguish "not set" from "explicitly set to false"
	// in contexts where the default varies (e.g., cloud images default to true).
	// TODO: consider refactoring to use *bool or restructuring context-specific defaults.
	ExternalBuildSet bool

	// FIPSBuild indicates whether to build FIPS-compliant binaries (from FIPS env var)
	FIPSBuild bool

	// VersionQualifier is the version qualifier suffix e.g., "rc1" (from VERSION_QUALIFIER env var)
	VersionQualifier string

	// VersionQualified indicates whether a version qualifier is set
	VersionQualified bool

	// CI indicates we're running in a CI environment (from CI env var)
	CI string

	// MaxParallel is the maximum number of parallel jobs (from MAX_PARALLEL env var)
	MaxParallel int

	// BeatVersion overrides the beat version (from BEAT_VERSION or set programmatically)
	BeatVersion string

	// AgentCommitHashOverride overrides the commit hash for packaging (from AGENT_COMMIT_HASH_OVERRIDE or set programmatically)
	AgentCommitHashOverride string

	// commitHash is the commit hash of the current build. Can be overridden via the AGENT_COMMIT_HASH_OVERRIDE env var.
	// We lazy load this value, because inside crossbuild containers, fetching it can fail.
	commitHash string

	// GolangCrossBuild indicates we're inside a golang-crossbuild container (from GOLANG_CROSSBUILD env var)
	GolangCrossBuild bool

	// BeatGoVersion overrides the Go version (from BEAT_GO_VERSION env var)
	BeatGoVersion string

	// BeatDocBranch overrides the documentation branch (from BEAT_DOC_BRANCH env var)
	BeatDocBranch string
}

func (bs *BuildSettings) CommitHash() (string, error) {
	if bs.AgentCommitHashOverride != "" {
		return bs.AgentCommitHashOverride, nil
	}
	if bs.commitHash == "" {
		var err error
		bs.commitHash, err = sh.Output("git", "rev-parse", "HEAD")
		if err != nil {
			return "", fmt.Errorf("failed to get commit hash: %w", err)
		}
	}
	return bs.commitHash, nil
}

func (bs *BuildSettings) CommitHashShort() (string, error) {
	shortHash, err := bs.CommitHash()
	if err != nil {
		return "", err
	}
	if len(shortHash) > 6 {
		shortHash = shortHash[:6]
	}
	return shortHash, nil
}

// BeatSettings contains Beat metadata settings.
type BeatSettings struct {
	// Name is the project name (from BEAT_NAME env var, default "elastic-agent")
	Name string

	// ServiceName is the service name (from BEAT_SERVICE_NAME env var, default BeatName)
	ServiceName string

	// IndexPrefix is the Elasticsearch index prefix (from BEAT_INDEX_PREFIX env var, default BeatName)
	IndexPrefix string

	// Description is the project description (from BEAT_DESCRIPTION env var)
	Description string

	// Vendor is the vendor name (from BEAT_VENDOR env var, default "Elastic")
	Vendor string

	// License is the license type (from BEAT_LICENSE env var, default "Elastic License 2.0")
	License string

	// URL is the project URL (from BEAT_URL env var)
	URL string

	// User is the default user for packages (from BEAT_USER env var, default "root")
	User string
}

// TestSettings contains test-related settings.
type TestSettings struct {
	// RaceDetector enables the Go race detector (from RACE_DETECTOR env var)
	RaceDetector bool

	// Coverage enables code coverage profiling (from TEST_COVERAGE env var)
	Coverage bool

	// Tags is a list of build tags for tests (from TEST_TAGS env var)
	Tags []string
}

// CrossBuildSettings contains cross-build settings.
type CrossBuildSettings struct {
	// Platforms is the comma-separated list of target platforms (from PLATFORMS env var)
	Platforms string

	// Packages is the comma-separated list of package types (from PACKAGES env var)
	Packages string

	// DockerVariants is the comma-separated list of Docker variants (from DOCKER_VARIANTS env var)
	DockerVariants string

	// MountModcache enables mounting $GOPATH/pkg/mod into crossbuild containers (from CROSSBUILD_MOUNT_MODCACHE env var)
	MountModcache bool

	// MountBuildCache enables mounting Go build cache into crossbuild containers (from CROSSBUILD_MOUNT_GOCACHE env var)
	MountBuildCache bool

	// BuildCacheVolumeName is the Docker volume name for the build cache
	BuildCacheVolumeName string

	// DevOS is the target OS for config generation (from DEV_OS env var, default "linux")
	DevOS string

	// DevArch is the target architecture for config generation (from DEV_ARCH env var, default "amd64")
	DevArch string
}

// PackagingSettings contains packaging-related settings.
type PackagingSettings struct {
	// AgentPackageVersion overrides the package version (from AGENT_PACKAGE_VERSION env var)
	AgentPackageVersion string

	// ManifestURL is the location of manifest file for packaging (from MANIFEST_URL env var)
	ManifestURL string

	// PackagingFromManifest indicates whether to use manifest for packaging (derived from ManifestURL)
	PackagingFromManifest bool

	// UsePackageVersion enables reading version from .package-version file (from USE_PACKAGE_VERSION env var)
	UsePackageVersion bool

	// AgentDropPath is the path for dropping agent artifacts (from AGENT_DROP_PATH env var)
	AgentDropPath string

	// KeepArchive indicates whether to keep the archive after packaging (from KEEP_ARCHIVE env var)
	KeepArchive bool
}

// IntegrationTestSettings contains integration test related settings.
type IntegrationTestSettings struct {
	// AgentVersion is the agent version for integration tests (from AGENT_VERSION env var)
	AgentVersion string

	// AgentStackVersion is the stack version for integration tests (from AGENT_STACK_VERSION env var)
	AgentStackVersion string

	// AgentBuildDir is the build directory for agent artifacts (from AGENT_BUILD_DIR env var)
	AgentBuildDir string

	// StackProvisioner specifies the stack provisioner to use (from STACK_PROVISIONER env var)
	// Valid values: "stateful", "serverless"
	StackProvisioner string

	// InstanceProvisioner specifies the instance provisioner to use (from INSTANCE_PROVISIONER env var)
	// Valid values: "ogc", "multipass", "kind"
	InstanceProvisioner string

	// ESSRegion is the ESS region for testing (from TEST_INTEG_AUTH_ESS_REGION env var)
	ESSRegion string

	// GCPDatacenter is the GCP datacenter for testing (from TEST_INTEG_AUTH_GCP_DATACENTER env var)
	GCPDatacenter string

	// GCPProject is the GCP project for testing (from TEST_INTEG_AUTH_GCP_PROJECT env var)
	GCPProject string

	// GCPEmailDomain is the expected email domain for GCP auth (from TEST_INTEG_AUTH_EMAIL_DOMAIN env var)
	GCPEmailDomain string

	// GCPServiceTokenFile is the path to GCP service token file (from TEST_INTEG_AUTH_GCP_SERVICE_TOKEN_FILE env var)
	GCPServiceTokenFile string

	// Platforms specifies the test platforms (from TEST_PLATFORMS env var)
	Platforms string

	// Packages specifies the test packages (from TEST_PACKAGES env var)
	Packages string

	// Groups specifies the test groups (from TEST_GROUPS env var)
	Groups string

	// DefinePrefix is the test define prefix (from TEST_DEFINE_PREFIX env var)
	DefinePrefix string

	// DefineTests specifies the tests to run (from TEST_DEFINE_TESTS env var)
	DefineTests string

	// BinaryName is the binary name for testing (from TEST_BINARY_NAME env var)
	BinaryName string

	// RepoPath is the repository path for testing (from TEST_INTEG_REPO_PATH env var)
	RepoPath string

	// TimestampEnabled enables timestamps in test output (from TEST_INTEG_TIMESTAMP env var)
	TimestampEnabled bool

	// RunUntilFailure runs tests until a failure occurs (from TEST_RUN_UNTIL_FAILURE env var)
	RunUntilFailure bool

	// CleanOnExit cleans up on exit (from TEST_INTEG_CLEAN_ON_EXIT env var)
	CleanOnExit bool

	// LongRunning enables long running tests (from TEST_LONG_RUNNING env var)
	LongRunning string

	// LongTestRuntime specifies the runtime for long tests (from LONG_TEST_RUNTIME env var)
	LongTestRuntime string

	// CollectDiag enables diagnostic collection (from AGENT_COLLECT_DIAG env var)
	CollectDiag string

	// KeepInstalled keeps the agent installed after tests (from AGENT_KEEP_INSTALLED env var)
	KeepInstalled string

	// BuildAgent indicates whether to build the agent before tests (from BUILD_AGENT env var)
	BuildAgent bool

	// GoTestFlags contains additional flags for go test (from GOTEST_FLAGS env var)
	GoTestFlags string

	// TestEnvironmentEnabled indicates if the test environment is enabled (from TEST_ENVIRONMENT env var).
	// Defaults to true if not set.
	TestEnvironmentEnabled bool
}

// DockerSettings contains Docker-related settings.
type DockerSettings struct {
	// ImportSource overrides the docker import source (from DOCKER_IMPORT_SOURCE env var)
	ImportSource string

	// CustomImageTag overrides the docker image tag (from CUSTOM_IMAGE_TAG env var)
	CustomImageTag string

	// CIElasticAgentDockerImage overrides the CI docker image (from CI_ELASTIC_AGENT_DOCKER_IMAGE env var)
	CIElasticAgentDockerImage string

	// NoCache disables docker build cache (from DOCKER_NOCACHE env var)
	NoCache bool

	// ForcePull forces docker to pull images (from DOCKER_PULL env var)
	ForcePull bool

	// WindowsNpcap enables Windows NPCAP support (from WINDOWS_NPCAP env var)
	WindowsNpcap bool
}

// KubernetesSettings contains Kubernetes-related settings.
type KubernetesSettings struct {
	// K8sVersion is the Kubernetes version (from K8S_VERSION env var)
	K8sVersion string

	// KindSkipDelete skips Kind cluster deletion (from KIND_SKIP_DELETE env var)
	KindSkipDelete bool
}

// DevMachineSettings contains settings for dev machine provisioning.
type DevMachineSettings struct {
	// MachineImage is the GCP machine image to use (from MACHINE_IMAGE env var)
	// Defaults to "family/platform-ingest-elastic-agent-ubuntu-2204"
	MachineImage string

	// Zone is the GCP zone to use (from ZONE env var)
	// Defaults to "us-central1-a"
	Zone string
}

// FmtSettings contains settings for formatting tools.
type FmtSettings struct {
	// CheckHeadersDisabled disables license header checking (from CHECK_HEADERS_DISABLED env var)
	CheckHeadersDisabled bool
}

// MustLoadSettings reads all settings from environment variables and returns a new Settings.
// It panics if settings loading fails. Use this when you need settings but don't have a context.
func MustLoadSettings() *Settings {
	s, err := LoadSettings()
	if err != nil {
		panic(fmt.Errorf("failed to load settings: %w", err))
	}
	return s
}

// LoadSettings reads all settings from environment variables and returns a new Settings.
// Each call returns a fresh settings with defaults, then overridden by environment variables.
func LoadSettings() (*Settings, error) {
	s := DefaultSettings()

	if err := s.loadBuildSettingsFromEnv(); err != nil {
		return nil, fmt.Errorf("loading build settings: %w", err)
	}

	s.loadBeatSettingsFromEnv()

	if err := s.loadTestSettingsFromEnv(); err != nil {
		return nil, fmt.Errorf("loading test settings: %w", err)
	}

	s.loadCrossBuildSettingsFromEnv()
	s.loadPackagingSettingsFromEnv()
	if err := s.loadIntegrationTestSettingsFromEnv(); err != nil {
		return nil, fmt.Errorf("loading integration test settings: %w", err)
	}
	s.loadDockerSettingsFromEnv()
	s.loadKubernetesSettingsFromEnv()
	s.loadDevMachineSettingsFromEnv()
	s.loadFmtSettingsFromEnv()

	return s, nil
}

// loadBuildSettingsFromEnv overrides build settings from environment variables.
// Defaults should already be set via setBuildDefaults().
func (s *Settings) loadBuildSettingsFromEnv() error {
	if v := os.Getenv("GOARM"); v != "" {
		s.Build.GOARM = v
	}
	if v := os.Getenv("CI"); v != "" {
		s.Build.CI = v
	}

	var err error

	_, s.Build.SnapshotSet = os.LookupEnv("SNAPSHOT")
	s.Build.Snapshot, err = parseBoolEnv("SNAPSHOT", s.Build.Snapshot)
	if err != nil {
		return fmt.Errorf("failed to parse SNAPSHOT: %w", err)
	}

	s.Build.DevBuild, err = parseBoolEnv("DEV", s.Build.DevBuild)
	if err != nil {
		return fmt.Errorf("failed to parse DEV: %w", err)
	}

	_, s.Build.ExternalBuildSet = os.LookupEnv("EXTERNAL")
	s.Build.ExternalBuild, err = parseBoolEnv("EXTERNAL", s.Build.ExternalBuild)
	if err != nil {
		return fmt.Errorf("failed to parse EXTERNAL: %w", err)
	}

	s.Build.FIPSBuild, err = parseBoolEnv("FIPS", s.Build.FIPSBuild)
	if err != nil {
		return fmt.Errorf("failed to parse FIPS: %w", err)
	}

	s.Build.VersionQualifier, s.Build.VersionQualified = os.LookupEnv("VERSION_QUALIFIER")

	// Parse MAX_PARALLEL - only override if set
	if maxParallel := os.Getenv("MAX_PARALLEL"); maxParallel != "" {
		if num, err := strconv.Atoi(maxParallel); err == nil && num > 0 {
			s.Build.MaxParallel = num
		}
	}

	if v := os.Getenv("BEAT_VERSION"); v != "" {
		s.Build.BeatVersion = v
	}

	if v := os.Getenv("AGENT_COMMIT_HASH_OVERRIDE"); v != "" {
		s.Build.AgentCommitHashOverride = v
	}

	s.Build.GolangCrossBuild = os.Getenv("GOLANG_CROSSBUILD") == "1"

	if v := os.Getenv("BEAT_GO_VERSION"); v != "" {
		s.Build.BeatGoVersion = v
	}

	if v := os.Getenv("BEAT_DOC_BRANCH"); v != "" {
		s.Build.BeatDocBranch = v
	}

	return nil
}

// loadBeatSettingsFromEnv overrides beat settings from environment variables.
// Defaults should already be set via setBeatDefaults().
func (s *Settings) loadBeatSettingsFromEnv() {
	if v := os.Getenv("BEAT_NAME"); v != "" {
		s.Beat.Name = v
		// Update dependent defaults if BeatName changed and they weren't explicitly set
		if os.Getenv("BEAT_SERVICE_NAME") == "" {
			s.Beat.ServiceName = v
		}
		if os.Getenv("BEAT_INDEX_PREFIX") == "" {
			s.Beat.IndexPrefix = v
		}
		if os.Getenv("BEAT_URL") == "" {
			s.Beat.URL = "https://www.elastic.co/beats/" + v
		}
	}
	if v := os.Getenv("BEAT_SERVICE_NAME"); v != "" {
		s.Beat.ServiceName = v
	}
	if v := os.Getenv("BEAT_INDEX_PREFIX"); v != "" {
		s.Beat.IndexPrefix = v
	}
	if v := os.Getenv("BEAT_DESCRIPTION"); v != "" {
		s.Beat.Description = v
	}
	if v := os.Getenv("BEAT_VENDOR"); v != "" {
		s.Beat.Vendor = v
	}
	if v := os.Getenv("BEAT_LICENSE"); v != "" {
		s.Beat.License = v
	}
	if v := os.Getenv("BEAT_URL"); v != "" {
		s.Beat.URL = v
	}
	if v := os.Getenv("BEAT_USER"); v != "" {
		s.Beat.User = v
	}
}

// loadTestSettingsFromEnv overrides test settings from environment variables.
// Defaults should already be set via setTestDefaults().
func (s *Settings) loadTestSettingsFromEnv() error {
	var err error

	s.Test.RaceDetector, err = parseBoolEnv("RACE_DETECTOR", s.Test.RaceDetector)
	if err != nil {
		return fmt.Errorf("failed to parse RACE_DETECTOR: %w", err)
	}

	s.Test.Coverage, err = parseBoolEnv("TEST_COVERAGE", s.Test.Coverage)
	if err != nil {
		return fmt.Errorf("failed to parse TEST_COVERAGE: %w", err)
	}

	if tags := os.Getenv("TEST_TAGS"); tags != "" {
		s.Test.Tags = strings.Split(strings.Trim(tags, ", "), ",")
	}

	return nil
}

// loadCrossBuildSettingsFromEnv overrides cross-build settings from environment variables.
// Defaults should already be set via setCrossBuildDefaults().
func (s *Settings) loadCrossBuildSettingsFromEnv() {
	if v := os.Getenv("PLATFORMS"); v != "" {
		s.CrossBuild.Platforms = v
	}
	if v := os.Getenv("PACKAGES"); v != "" {
		s.CrossBuild.Packages = v
	}
	if v := os.Getenv("DOCKER_VARIANTS"); v != "" {
		s.CrossBuild.DockerVariants = v
	}
	if v, ok := os.LookupEnv("CROSSBUILD_MOUNT_MODCACHE"); ok {
		s.CrossBuild.MountModcache = v == "true"
	}
	if v, ok := os.LookupEnv("CROSSBUILD_MOUNT_GOCACHE"); ok {
		s.CrossBuild.MountBuildCache = v == "true"
	}
	if v := os.Getenv("DEV_OS"); v != "" {
		s.CrossBuild.DevOS = v
	}
	if v := os.Getenv("DEV_ARCH"); v != "" {
		s.CrossBuild.DevArch = v
	}
}

// loadPackagingSettingsFromEnv overrides packaging settings from environment variables.
// Defaults should already be set via setPackagingDefaults().
func (s *Settings) loadPackagingSettingsFromEnv() {
	if v := os.Getenv("AGENT_PACKAGE_VERSION"); v != "" {
		s.Packaging.AgentPackageVersion = v
	}
	if v := os.Getenv("MANIFEST_URL"); v != "" {
		s.Packaging.ManifestURL = v
		s.Packaging.PackagingFromManifest = true
	}
	if os.Getenv("USE_PACKAGE_VERSION") == "true" {
		s.Packaging.UsePackageVersion = true
	}
	if v := os.Getenv("AGENT_DROP_PATH"); v != "" {
		s.Packaging.AgentDropPath = v
	}
	if _, ok := os.LookupEnv("KEEP_ARCHIVE"); ok {
		s.Packaging.KeepArchive = true
	}
}

// loadIntegrationTestSettingsFromEnv overrides integration test settings from environment variables.
// Defaults should already be set via setIntegrationTestDefaults().
func (s *Settings) loadIntegrationTestSettingsFromEnv() error {
	if v := os.Getenv("AGENT_VERSION"); v != "" {
		s.IntegrationTest.AgentVersion = v
	}
	if v := os.Getenv("AGENT_STACK_VERSION"); v != "" {
		s.IntegrationTest.AgentStackVersion = v
	}
	if v := os.Getenv("AGENT_BUILD_DIR"); v != "" {
		s.IntegrationTest.AgentBuildDir = v
	}
	if v := os.Getenv("STACK_PROVISIONER"); v != "" {
		s.IntegrationTest.StackProvisioner = v
	}
	if v := os.Getenv("INSTANCE_PROVISIONER"); v != "" {
		s.IntegrationTest.InstanceProvisioner = v
	}
	if v := os.Getenv("TEST_INTEG_AUTH_ESS_REGION"); v != "" {
		s.IntegrationTest.ESSRegion = v
	}
	if v := os.Getenv("TEST_INTEG_AUTH_GCP_DATACENTER"); v != "" {
		s.IntegrationTest.GCPDatacenter = v
	}
	if v := os.Getenv("TEST_INTEG_AUTH_GCP_PROJECT"); v != "" {
		s.IntegrationTest.GCPProject = v
	}
	if v := os.Getenv("TEST_INTEG_AUTH_EMAIL_DOMAIN"); v != "" {
		s.IntegrationTest.GCPEmailDomain = v
	}
	if v := os.Getenv("TEST_INTEG_AUTH_GCP_SERVICE_TOKEN_FILE"); v != "" {
		s.IntegrationTest.GCPServiceTokenFile = v
	}
	if v := os.Getenv("TEST_PLATFORMS"); v != "" {
		s.IntegrationTest.Platforms = v
	}
	if v := os.Getenv("TEST_PACKAGES"); v != "" {
		s.IntegrationTest.Packages = v
	}
	if v := os.Getenv("TEST_GROUPS"); v != "" {
		s.IntegrationTest.Groups = v
	}
	if v := os.Getenv("TEST_DEFINE_PREFIX"); v != "" {
		s.IntegrationTest.DefinePrefix = v
	}
	if v := os.Getenv("TEST_DEFINE_TESTS"); v != "" {
		s.IntegrationTest.DefineTests = v
	}
	if v := os.Getenv("TEST_BINARY_NAME"); v != "" {
		s.IntegrationTest.BinaryName = v
	}
	if v := os.Getenv("TEST_INTEG_REPO_PATH"); v != "" {
		s.IntegrationTest.RepoPath = v
	}
	if os.Getenv("TEST_INTEG_TIMESTAMP") == "true" {
		s.IntegrationTest.TimestampEnabled = true
	}
	if os.Getenv("TEST_RUN_UNTIL_FAILURE") == "true" {
		s.IntegrationTest.RunUntilFailure = true
	}
	if os.Getenv("TEST_INTEG_CLEAN_ON_EXIT") == "false" {
		s.IntegrationTest.CleanOnExit = false
	}
	if v := os.Getenv("TEST_LONG_RUNNING"); v != "" {
		s.IntegrationTest.LongRunning = v
	}
	if v := os.Getenv("LONG_TEST_RUNTIME"); v != "" {
		s.IntegrationTest.LongTestRuntime = v
	}
	if v := os.Getenv("AGENT_COLLECT_DIAG"); v != "" {
		s.IntegrationTest.CollectDiag = v
	}
	if v := os.Getenv("AGENT_KEEP_INSTALLED"); v != "" {
		s.IntegrationTest.KeepInstalled = v
	}
	if os.Getenv("BUILD_AGENT") == "true" {
		s.IntegrationTest.BuildAgent = true
	}
	if v := os.Getenv("GOTEST_FLAGS"); v != "" {
		s.IntegrationTest.GoTestFlags = v
	}

	var err error
	s.IntegrationTest.TestEnvironmentEnabled, err = parseBoolEnv("TEST_ENVIRONMENT", s.IntegrationTest.TestEnvironmentEnabled)
	if err != nil {
		return fmt.Errorf("failed to parse TEST_ENVIRONMENT: %w", err)
	}

	return nil
}

// loadDockerSettingsFromEnv overrides Docker settings from environment variables.
// Defaults should already be set via setDockerDefaults().
func (s *Settings) loadDockerSettingsFromEnv() {
	if v := os.Getenv("DOCKER_IMPORT_SOURCE"); v != "" {
		s.Docker.ImportSource = v
	}
	if v := os.Getenv("CUSTOM_IMAGE_TAG"); v != "" {
		s.Docker.CustomImageTag = v
	}
	if v := os.Getenv("CI_ELASTIC_AGENT_DOCKER_IMAGE"); v != "" {
		s.Docker.CIElasticAgentDockerImage = v
	}
	if _, ok := os.LookupEnv("DOCKER_NOCACHE"); ok {
		s.Docker.NoCache = true
	}
	if _, ok := os.LookupEnv("DOCKER_PULL"); ok {
		s.Docker.ForcePull = true
	}
	if os.Getenv("WINDOWS_NPCAP") == "true" {
		s.Docker.WindowsNpcap = true
	}
}

// loadKubernetesSettingsFromEnv overrides Kubernetes settings from environment variables.
// Defaults should already be set via setKubernetesDefaults().
func (s *Settings) loadKubernetesSettingsFromEnv() {
	if v := os.Getenv("K8S_VERSION"); v != "" {
		s.Kubernetes.K8sVersion = v
	}
	if os.Getenv("KIND_SKIP_DELETE") == "true" {
		s.Kubernetes.KindSkipDelete = true
	}
}

// loadDevMachineSettingsFromEnv overrides dev machine settings from environment variables.
// Defaults should already be set via setDevMachineDefaults().
func (s *Settings) loadDevMachineSettingsFromEnv() {
	if v := os.Getenv("MACHINE_IMAGE"); v != "" {
		s.DevMachine.MachineImage = v
	}
	if v := os.Getenv("ZONE"); v != "" {
		s.DevMachine.Zone = v
	}
}

// loadFmtSettingsFromEnv overrides formatting settings from environment variables.
// Defaults should already be set via setFmtDefaults().
func (s *Settings) loadFmtSettingsFromEnv() {
	if _, ok := os.LookupEnv("CHECK_HEADERS_DISABLED"); ok {
		s.Fmt.CheckHeadersDisabled = true
	}
}

// parseBoolEnv parses a boolean environment variable with a default value.
func parseBoolEnv(name string, def bool) (bool, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	return strconv.ParseBool(v)
}

// BinaryExt returns the appropriate binary extension for the configured GOOS.
func (s *Settings) BinaryExt() string {
	if s.Build.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// Platform returns platform attributes for the current build settings.
func (s *Settings) Platform() PlatformAttributes {
	return MakePlatformAttributes(s.Build.GOOS, s.Build.GOARCH, s.Build.GOARM)
}

// TestTagsWithFIPS returns the test tags, including FIPS-related tags if FIPSBuild is enabled.
func (s *Settings) TestTagsWithFIPS() []string {
	tags := make([]string, len(s.Test.Tags))
	copy(tags, s.Test.Tags)
	if s.Build.FIPSBuild {
		tags = append(tags, "requirefips", "ms_tls13kdf")
	}
	return tags
}

// GetPlatforms returns the parsed platform list from PLATFORMS env var.
// If PLATFORMS is empty, returns the default platform list.
// Platform filters from the settings' PlatformFilters are applied to the result.
// Note: linux/386 and windows/386 are always filtered out as they are not supported.
func (s *Settings) GetPlatforms() BuildPlatformList {
	var platforms BuildPlatformList
	if s.CrossBuild.Platforms != "" {
		platforms = NewPlatformList(s.CrossBuild.Platforms)
	} else {
		platforms = BuildPlatforms.Defaults()
	}

	// Filter out unsupported platforms
	platforms = platforms.Filter("!linux/386")
	platforms = platforms.Filter("!windows/386")

	// Apply platform filters from settings
	for _, filter := range s.PlatformFilters {
		platforms = platforms.Filter(filter)
	}

	return platforms
}

// GetPackageTypes returns the package types to use.
// If SelectedPackageTypes is set in the settings, returns that.
// Otherwise parses from PACKAGES env var.
// If PACKAGES is empty, returns nil (meaning all package types are selected).
func (s *Settings) GetPackageTypes() []PackageType {
	// Check settings override first
	if s.SelectedPackageTypes != nil {
		return s.SelectedPackageTypes
	}
	// Fall back to env var
	if s.CrossBuild.Packages == "" {
		return nil
	}
	var types []PackageType
	for _, pkgtype := range strings.Split(s.CrossBuild.Packages, ",") {
		var p PackageType
		if err := p.UnmarshalText([]byte(pkgtype)); err == nil {
			types = append(types, p)
		}
	}
	return types
}

// GetDockerVariants returns the docker variants to use.
// If SelectedDockerVariants is set in the settings, returns that.
// Otherwise parses from DOCKER_VARIANTS env var.
// If DOCKER_VARIANTS is empty, returns nil (meaning all variants are selected).
func (s *Settings) GetDockerVariants() []DockerVariant {
	// Check settings override first
	if s.SelectedDockerVariants != nil {
		return s.SelectedDockerVariants
	}
	// Fall back to env var
	if s.CrossBuild.DockerVariants == "" {
		return nil
	}
	var variants []DockerVariant
	for _, variant := range strings.Split(s.CrossBuild.DockerVariants, ",") {
		var v DockerVariant
		if err := v.UnmarshalText([]byte(variant)); err == nil {
			variants = append(variants, v)
		}
	}
	return variants
}

// IsPackageTypeSelected returns true if SelectedPackageTypes is empty or if
// pkgType is present on SelectedPackageTypes. It returns false otherwise.
func (s *Settings) IsPackageTypeSelected(pkgType PackageType) bool {
	selectedTypes := s.GetPackageTypes()
	if len(selectedTypes) == 0 {
		return true
	}

	for _, t := range selectedTypes {
		if t == pkgType {
			return true
		}
	}
	return false
}

// IsDockerVariantSelected returns true if SelectedDockerVariants is empty or if
// docVariant is present on SelectedDockerVariants. It returns false otherwise.
func (s *Settings) IsDockerVariantSelected(docVariant DockerVariant) bool {
	selectedVariants := s.GetDockerVariants()
	if len(selectedVariants) == 0 {
		return true
	}

	for _, v := range selectedVariants {
		if v == docVariant {
			return true
		}
	}
	return false
}
