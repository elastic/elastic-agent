package packaging

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"log"

	"github.com/magefile/mage/mg"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/dev-tools/mage/pkgcommon"
)

var PlatformPackages = map[string]string{
	"darwin/amd64":  "darwin-x86_64.tar.gz",
	"darwin/arm64":  "darwin-aarch64.tar.gz",
	"linux/amd64":   "linux-x86_64.tar.gz",
	"linux/arm64":   "linux-arm64.tar.gz",
	"windows/amd64": "windows-x86_64.zip",
}

type BinarySpec struct {
	BinaryName   string                  `yaml:"binaryName"`
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
	if proj.PythonWheel {
		return fmt.Sprintf("%s-%s.zip", proj.BinaryName, version)
	}
	return fmt.Sprintf("%s-%s-%s", proj.BinaryName, version, PlatformPackages[platform])
}

// ExpectedBinaries  is a map of binaries agent needs to their project in the unified-release manager.
// The project names are those used in the "projects" list in the unified release manifest.
// See the sample manifests in the testdata directory.
var ExpectedBinaries []BinarySpec

type Platform struct {
	OS   string
	Arch string
}

// Converts to the format expected on the mage command line "linux", "x86_64" = "linux/amd64"
func (p Platform) Platform() string {
	if p.Arch == "x86_64" {
		p.Arch = "amd64"
	}
	if p.Arch == "aarch64" {
		p.Arch = "arm64"
	}
	return p.OS + "/" + p.Arch
}

//go:embed packages.yml
var packageSpecBytes []byte

func init() {
	packageSettings, err := parsePackageSettings(bytes.NewReader(packageSpecBytes))
	if err != nil {
		log.Printf("Error loading package settings: %v", err)
		return
	}

	ExpectedBinaries = packageSettings.Components
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
