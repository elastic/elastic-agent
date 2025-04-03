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
	"text/template"

	"github.com/magefile/mage/mg"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/dev-tools/mage/pkgcommon"
)

var (
	//go:embed packages.yml
	packageSpecBytes []byte
	PlatformPackages = map[string]platformAndExt{
		"darwin/amd64": {
			platform: "darwin-x86_64",
			ext:      "tar.gz",
		},
		"darwin/arm64": {
			platform: "darwin-aarch64",
			ext:      "tar.gz",
		},
		"linux/amd64": {
			platform: "linux-x86_64",
			ext:      "tar.gz",
		},
		"linux/arm64": {
			platform: "linux-arm64",
			ext:      "tar.gz",
		},
		"windows/amd64": {
			platform: "windows-x86_64",
			ext:      "zip",
		},
	}
	// ExpectedBinaries  is a map of binaries agent needs to their project in the unified-release manager.
	// The project names are those used in the "projects" list in the unified release manifest.
	// See the sample manifests in the testdata directory.
	ExpectedBinaries []BinarySpec
)

func init() {
	packageSettings, err := parsePackageSettings(bytes.NewReader(packageSpecBytes))
	if err != nil {
		log.Printf("Error loading package settings: %v", err)
		return
	}

	ExpectedBinaries = packageSettings.Components
}

type platformAndExt struct {
	platform string
	ext      string
}

type BinarySpec struct {
	BinaryName   string                  `yaml:"binaryName"`
	PackageName  string                  `yaml:"packageName"`
	ProjectName  string                  `yaml:"projectName"`
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

func (proj BinarySpec) GetPackageName(version string, platform string) string {
	tmpl, err := template.New("package_name").Parse(proj.PackageName)
	if err != nil {
		panic(fmt.Errorf("parsing packageName template for project/binary %s/%s %q: %w", proj.ProjectName, proj.BinaryName, proj.PackageName, err))
	}

	// look for the platform strings, if not found an empty object is returned and empty values will be used for rendering
	pltfStrings := PlatformPackages[platform]
	tmplContext := map[string]string{"Version": version, "Platform": pltfStrings.platform, "Ext": pltfStrings.ext}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, tmplContext)
	if err != nil {
		panic(fmt.Errorf("rendering packageName template for project/binary %s/%s %q with context %v: %w",
			proj.ProjectName, proj.BinaryName, proj.PackageName, tmplContext, err))
	}
	return buf.String()
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

type packagesConfig struct {
	Platforms    []Platform              `yaml:"platforms"`
	PackageTypes []pkgcommon.PackageType `yaml:"packageTypes"`
	Components   []BinarySpec            `yaml:"components"`
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
