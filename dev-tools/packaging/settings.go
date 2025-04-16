// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package packaging

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"log"
	"slices"
	"text/template"

	"github.com/magefile/mage/mg"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/dev-tools/mage/pkgcommon"
)

var (
	//go:embed packages.yml
	packageSpecBytes []byte
	platformPackages = map[string]platformAndExt{
		"darwin/amd64": {
			platform: "darwin-x86_64",
			os:       "darwin",
			arch:     "amd64",
			ext:      "tar.gz",
		},
		"darwin/arm64": {
			platform: "darwin-aarch64",
			os:       "darwin",
			arch:     "arm64",
			ext:      "tar.gz",
		},
		"linux/amd64": {
			platform: "linux-x86_64",
			os:       "linux",
			arch:     "amd64",
			ext:      "tar.gz",
		},
		"linux/arm64": {
			platform: "linux-arm64",
			os:       "linux",
			arch:     "arm64",
			ext:      "tar.gz",
		},
		"windows/amd64": {
			platform: "windows-x86_64",
			os:       "windows",
			arch:     "amd64",
			ext:      "zip",
		},
	}
	settings *packagesConfig
)

func init() {
	packageSettings, err := parsePackageSettings(bytes.NewReader(packageSpecBytes))
	if err != nil {
		log.Printf("Error loading package settings: %v", err)
		return
	}

	settings = packageSettings
}

type platformAndExt struct {
	platform string
	os       string
	arch     string
	ext      string
}

type BinarySpec struct {
	BinaryName   string                  `yaml:"binaryName"`
	PackageName  string                  `yaml:"packageName"`
	RootDir      string                  `yaml:"rootDir"`
	ProjectName  string                  `yaml:"projectName"`
	FIPS         bool                    `yaml:"fips"`
	Platforms    []Platform              `yaml:"platforms"`
	PythonWheel  bool                    `yaml:"pythonWheel"`
	PackageTypes []pkgcommon.PackageType `yaml:"packageTypes"`
}

func (proj BinarySpec) SupportsPlatform(platform string) bool {
	for _, p := range proj.Platforms {
		if p.Platform() == platform {
			return true
		}
	}
	return false
}

func (proj BinarySpec) SupportsPackageType(pkgType pkgcommon.PackageType) bool {
	for _, p := range proj.PackageTypes {
		if p == pkgType {
			return true
		}
	}
	return false
}

// GetPackageName will return a rendered version of the BinarySpec.packageName attribute (which is a golang template),
// using version and platform strings provided to create a template context containing 'Version', 'Platform' and 'Ext' values.
// The string returned will contain the expected filename of the package file for the BinarySpec
func (proj BinarySpec) GetPackageName(version string, platform string) string {
	tmpl, err := template.New("package_name").Parse(proj.PackageName)
	if err != nil {
		panic(fmt.Errorf("parsing packageName template for project/binary %s/%s %q: %w", proj.ProjectName, proj.BinaryName, proj.PackageName, err))
	}

	tmplContext := createTemplateContext(version, platform)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, tmplContext)
	if err != nil {
		panic(fmt.Errorf("rendering packageName template for project/binary %s/%s %q with context %v: %w",
			proj.ProjectName, proj.BinaryName, proj.PackageName, tmplContext, err))
	}
	return buf.String()
}

func createTemplateContext(version string, platform string) map[string]string {
	// look for the platform strings, if not found an empty object is returned and empty values will be used for rendering
	pltfStrings := platformPackages[platform]
	tmplContext := map[string]string{"Version": version, "Platform": pltfStrings.platform, "Ext": pltfStrings.ext, "OS": pltfStrings.os, "Arch": pltfStrings.arch}
	return tmplContext
}

// GetRootDir will return a rendered version of the BinarySpec.rootDir attribute (which is a golang template), using
// version and platform strings provided to create a template context containing 'Version', 'Platform' and 'Ext' values.
// The string returned will contain the expected name of the root directory created when extracted the package file for
// the BinarySpec
func (proj BinarySpec) GetRootDir(version string, platform string) string {
	if proj.RootDir == "" {
		// shortcut to avoid rendering template when there's no RootDir specified
		return ""
	}
	tmpl, err := template.New("rootDir").Parse(proj.RootDir)
	if err != nil {
		panic(fmt.Errorf("parsing rootDir template for project/binary %s/%s %q: %w", proj.ProjectName, proj.BinaryName, proj.RootDir, err))
	}

	tmplContext := createTemplateContext(version, platform)

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, tmplContext)
	if err != nil {
		panic(fmt.Errorf("rendering rootDir template for project/binary %s/%s %q with context %v: %w",
			proj.ProjectName, proj.BinaryName, proj.PackageName, tmplContext, err))
	}
	return buf.String()
}

func (proj BinarySpec) Equal(other BinarySpec) bool {
	if proj.BinaryName != other.BinaryName {
		return false
	}

	if proj.PackageName != other.PackageName {
		return false
	}

	if proj.RootDir != other.RootDir {
		return false
	}

	if proj.ProjectName != other.ProjectName {
		return false
	}

	if proj.FIPS != other.FIPS {
		return false
	}

	if !slices.Equal(proj.Platforms, other.Platforms) {
		return false
	}

	if proj.PythonWheel != other.PythonWheel {
		return false
	}

	if !slices.Equal(proj.PackageTypes, other.PackageTypes) {
		return false
	}

	return true
}

type Platform struct {
	OS   string
	Arch string
}

// Converts to the format expected on the mage command line "linux", "x86_64" = "linux/amd64"
func (p Platform) Platform() string {
	switch p.Arch {
	case "x86_64":
		p.Arch = "amd64"
	case "aarch64":
		p.Arch = "arm64"
	}
	return p.OS + "/" + p.Arch
}

type FIPSConfig struct {
	Compile struct {
		CGO       bool              `yaml:"cgo"`
		Env       map[string]string `yaml:"env"`
		Tags      []string          `yaml:"tags"`
		Platforms []Platform        `yaml:"platforms"`
	} `yaml:"compile"`
}

type GlobalSettings struct {
	FIPS FIPSConfig `yaml:"fips"`
}

type packagesConfig struct {
	Platforms    []Platform              `yaml:"platforms"`
	PackageTypes []pkgcommon.PackageType `yaml:"packageTypes"`
	Components   []BinarySpec            `yaml:"components"`
	Settings     GlobalSettings          `yaml:"settings"`
}

func parsePackageSettings(r io.Reader) (*packagesConfig, error) {
	packagesConf := new(packagesConfig)
	err := yaml.NewDecoder(r).Decode(packagesConf)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling package spec yaml: %w", err)
	}

	if mg.Verbose() {
		log.Printf("Read packages config: %+v", packagesConf)
	}
	return packagesConf, nil
}

// Components returns a *copy* of all the binary specs loaded from packages.yml
func Components() ([]BinarySpec, error) {
	if settings == nil {
		return nil, fmt.Errorf("package settings not loaded")
	}
	ret := make([]BinarySpec, len(settings.Components))
	copy(ret, settings.Components)
	return ret, nil
}

func Settings() GlobalSettings {
	return settings.Settings
}

func FilterComponents(filters ...ComponentFilter) []BinarySpec {
	ret := make([]BinarySpec, 0, len(settings.Components))

COMPLOOP:
	for _, c := range settings.Components {
		for _, filter := range filters {
			if !filter(c) {
				// this filter doesn't match, move to the next component
				continue COMPLOOP
			}
		}
		ret = append(ret, c)
	}
	return ret
}

type ComponentFilter func(BinarySpec) bool

func WithProjectName(projectName string) ComponentFilter {
	return func(p BinarySpec) bool {
		return p.ProjectName == projectName
	}
}

func WithFIPS(fips bool) ComponentFilter {
	return func(p BinarySpec) bool {
		return p.FIPS == fips
	}
}
