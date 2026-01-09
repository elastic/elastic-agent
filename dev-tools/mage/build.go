// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"context"
	"errors"
	"fmt"
	"go/build"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/josephspurrier/goversioninfo"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/elastic/elastic-agent/dev-tools/packaging"
)

// BuildArgs are the arguments used for the "build" target and they define how
// "go build" is invoked.
type BuildArgs struct {
	Name        string // Name of binary. (On Windows '.exe' is appended.)
	InputFiles  []string
	OutputDir   string
	CGO         bool
	Static      bool
	Env         map[string]string
	LDFlags     []string
	Vars        map[string]string // Vars that are passed as -X key=value with the ldflags.
	ExtraFlags  []string
	WinMetadata bool // Add resource metadata to Windows binaries (like add the version number to the .exe properties).
	Package     string
	WorkDir     string
}

// buildTagRE is a regexp to match strings like "-tags=abcd"
// but does not match "-tags= "
var buildTagRE = regexp.MustCompile(`-tags=([\S]+)?`)

// ParseBuildTags returns the ExtraFlags param where all flags that are go build tags are joined by a comma.
//
// For example if given -someflag=val1 -tags=buildtag1 -tags=buildtag2
// It will return -someflag=val1 -tags=buildtag1,buildtag2
func (b BuildArgs) ParseBuildTags() []string {
	flags := make([]string, 0)
	if len(b.ExtraFlags) == 0 {
		return flags
	}

	buildTags := make([]string, 0)
	for _, flag := range b.ExtraFlags {
		if buildTagRE.MatchString(flag) {
			arr := buildTagRE.FindStringSubmatch(flag)
			if len(arr) != 2 || arr[1] == "" {
				log.Printf("Unexpected format found for buildargs.ExtraFlags, ignoring value  %q", flag)
				continue
			}
			buildTags = append(buildTags, arr[1])
		} else {
			flags = append(flags, flag)
		}
	}
	if len(buildTags) > 0 {
		flags = append(flags, "-tags="+strings.Join(buildTags, ","))
	}
	return flags
}

// DefaultBuildArgs returns the default BuildArgs for use in builds.
func DefaultBuildArgs(cfg *Settings) BuildArgs {
	args := BuildArgs{
		Name: cfg.Beat.Name,
		CGO:  build.Default.CgoEnabled,
		Env:  map[string]string{},
		Vars: map[string]string{
			elasticAgentModulePath + "/version.buildTime": "{{ date }}",
			elasticAgentModulePath + "/version.commit":    "{{ commit }}",
		},
		WinMetadata: true,
	}
	if cfg.Build.VersionQualified {
		args.Vars[elasticAgentModulePath+"/version.qualifier"] = "{{ .Qualifier }}"
	}

	if positionIndependentCodeSupported(cfg) {
		args.ExtraFlags = append(args.ExtraFlags, "-buildmode", "pie")
	}

	if cfg.Build.FIPSBuild {
		fipsConfig := packaging.Settings().FIPS

		for _, tag := range fipsConfig.Compile.Tags {
			args.ExtraFlags = append(args.ExtraFlags, "-tags="+tag)
		}
		args.CGO = args.CGO || fipsConfig.Compile.CGO
		for varName, value := range fipsConfig.Compile.Env {
			args.Env[varName] = value
		}
	}

	if cfg.Build.DevBuild {
		// Disable optimizations (-N) and inlining (-l) for debugging.
		args.ExtraFlags = append(args.ExtraFlags, `-gcflags=all=-N -l`)
	} else {
		// Strip all debug symbols from binary (does not affect Go stack traces).
		args.LDFlags = append(args.LDFlags, "-s")
		// Remove all file system paths from the compiled executable, to improve build reproducibility
		args.ExtraFlags = append(args.ExtraFlags, "-trimpath")
	}

	return args
}

// positionIndependentCodeSupported checks if the target platform support position independent code (or ASLR).
//
// The list of supported platforms is compiled based on the Go release notes: https://golang.org/doc/devel/release.html
// The list has been updated according to the Go version: 1.16
func positionIndependentCodeSupported(cfg *Settings) bool {
	platform := cfg.Platform()
	return oneOf(platform.GOOS, "darwin") ||
		(platform.GOOS == "linux" && oneOf(platform.GOARCH, "riscv64", "amd64", "arm", "arm64", "ppc64le", "386")) ||
		(platform.GOOS == "aix" && platform.GOARCH == "ppc64") ||

		// Windows 32bit supports ASLR, but Windows Server 2003 and earlier do not.
		// According to the support matrix (https://www.elastic.co/support/matrix), these old versions
		// are not supported.
		(platform.GOOS == "windows")
}

func oneOf(value string, lst ...string) bool {
	for _, other := range lst {
		if other == value {
			return true
		}
	}
	return false
}

// DefaultGolangCrossBuildArgs returns the default BuildArgs for use in
// cross-builds.
func DefaultGolangCrossBuildArgs(cfg *Settings) BuildArgs {
	args := DefaultBuildArgs(cfg)
	platform := cfg.Platform()
	args.Name += "-" + platform.GOOS + "-" + platform.Arch
	args.OutputDir = filepath.Join("build", "golang-crossbuild")
	if bp, found := BuildPlatforms.Get(platform.Name); found {
		args.CGO = bp.Flags.SupportsCGO()
	}

	// Enable DEP (data execution protection) for Windows binaries.
	if platform.GOOS == "windows" {
		args.LDFlags = append(args.LDFlags, "-extldflags=-Wl,--nxcompat")
	}

	return args
}

// GolangCrossBuild invokes "go build" inside of the golang-crossbuild Docker
// environment.
func GolangCrossBuild(ctx context.Context, cfg *Settings, params BuildArgs) error {
	if !cfg.Build.GolangCrossBuild {
		return errors.New("use the crossBuild target. golangCrossBuild can " +
			"only be executed within the golang-crossbuild docker environment")
	}

	defer DockerChown(filepath.Join(params.OutputDir, params.Name+binaryExtension(cfg.Build.GOOS)))
	defer DockerChown(filepath.Join(params.OutputDir))

	mountPoint, err := ElasticBeatsDir()
	if err != nil {
		return err
	}
	if err := sh.Run("git", "config", "--global", "--add", "safe.directory", mountPoint); err != nil {
		return err
	}

	return Build(ctx, cfg, params)
}

// Build invokes "go build" to produce a binary.
func Build(ctx context.Context, cfg *Settings, params BuildArgs) error {
	fmt.Println(">> build: Building", params.Name)

	binaryName := params.Name + binaryExtension(cfg.Build.GOOS)

	if params.OutputDir != "" {
		if err := os.MkdirAll(params.OutputDir, 0755); err != nil {
			return err
		}
	}

	// Environment
	env := params.Env
	if env == nil {
		env = map[string]string{}
	}
	cgoEnabled := "0"
	if params.CGO {
		cgoEnabled = "1"
	}

	env["CGO_ENABLED"] = cgoEnabled

	// Spec
	outputDir, err := filepath.Abs(filepath.Join(params.OutputDir, binaryName))
	if err != nil {
		return fmt.Errorf("failed getting absolute path for %v: %w", params.OutputDir, err)
	}
	args := []string{
		"build",
		"-o",
		outputDir,
	}
	args = append(args, params.ParseBuildTags()...)

	// ldflags
	ldflags := params.LDFlags
	if params.Static {
		ldflags = append(ldflags, `-extldflags '-static'`)
	}
	for k, v := range params.Vars {
		ldflags = append(ldflags, fmt.Sprintf("-X %v=%v", k, v))
	}
	if len(ldflags) > 0 {
		args = append(args, "-ldflags")
		args = append(args, MustExpand(cfg, strings.Join(ldflags, " ")))
	}

	if len(params.InputFiles) > 0 {
		args = append(args, params.InputFiles...)
	}

	if cfg.Build.GOOS == "windows" && params.WinMetadata {
		log.Println("Generating a .syso containing Windows file metadata.")
		syso, err := MakeWindowsSysoFile(cfg)
		if err != nil {
			return fmt.Errorf("failed generating Windows .syso metadata file: %w", err)
		}
		defer os.Remove(syso)
	}

	if params.Package != "" {
		args = append(args, params.Package)
	}

	log.Println("Adding build environment vars:", env)
	var output io.Writer
	if mg.Verbose() {
		output = os.Stdout
	}
	return Run(ctx, env, output, os.Stderr, "go", params.WorkDir, args...)
}

func Run(ctx context.Context, env map[string]string, stdout, stderr io.Writer, cmd string, workingDir string, args ...string) (err error) {
	expand := func(s string) string {
		s2, ok := env[s]
		if ok {
			return s2
		}
		return os.Getenv(s)
	}
	cmd = os.Expand(cmd, expand)
	for i := range args {
		args[i] = os.Expand(args[i], expand)
	}

	c := exec.CommandContext(ctx, cmd, args...)
	c.Env = os.Environ()
	for k, v := range env {
		c.Env = append(c.Env, k+"="+v)
	}
	c.Dir = workingDir
	c.Stderr = stderr
	c.Stdout = stdout
	c.Stdin = os.Stdin

	var quoted []string
	for i := range args {
		quoted = append(quoted, fmt.Sprintf("%q", args[i]))
	}
	// To protect against logging from doing exec in global variables
	if mg.Verbose() {
		log.Println("exec:", cmd, strings.Join(quoted, " "))
	}
	err = c.Run()
	return err
}

// MakeWindowsSysoFile generates a .syso file containing metadata about the
// executable file like vendor, version, copyright. The linker automatically
// discovers the .syso file and incorporates it into the Windows exe. This
// allows users to view metadata about the exe in the Details tab of the file
// properties viewer.
func MakeWindowsSysoFile(cfg *Settings) (string, error) {
	version, err := BeatQualifiedVersion(cfg)
	if err != nil {
		return "", err
	}

	commit, err := cfg.Build.CommitHash()
	if err != nil {
		return "", err
	}

	major, minor, patch, err := ParseVersion(version)
	if err != nil {
		return "", err
	}
	fileVersion := goversioninfo.FileVersion{Major: major, Minor: minor, Patch: patch}

	vi := &goversioninfo.VersionInfo{
		FixedFileInfo: goversioninfo.FixedFileInfo{
			FileVersion:    fileVersion,
			ProductVersion: fileVersion,
			FileType:       "01", // Application
		},
		StringFileInfo: goversioninfo.StringFileInfo{
			CompanyName:      cfg.Beat.Vendor,
			ProductName:      cases.Title(language.Und, cases.NoLower).String(cfg.Beat.Name),
			ProductVersion:   version,
			FileVersion:      version,
			FileDescription:  cfg.Beat.Description,
			OriginalFilename: cfg.Beat.Name + ".exe",
			LegalCopyright:   "Copyright " + cfg.Beat.Vendor + ", License " + cfg.Beat.License,
			Comments:         "commit=" + commit,
		},
	}

	vi.Build()
	vi.Walk()
	sysoFile := cfg.Beat.Name + "_windows_" + cfg.Build.GOARCH + ".syso"
	if err = vi.WriteSyso(sysoFile, cfg.Build.GOARCH); err != nil {
		return "", fmt.Errorf("failed to generate syso file with Windows metadata: %w", err)
	}
	return sysoFile, nil
}
