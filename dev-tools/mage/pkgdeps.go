// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"

	"github.com/magefile/mage/sh"
)

// PackageInstaller contains package dependency
type PackageInstaller struct {
	table map[PlatformDescription][]PackageDependency
}

// PlatformDescription contains platform description
type PlatformDescription struct {
	Name       string
	Arch       string
	DefaultTag string
}

// PackageDependency contains package dependency details
type PackageDependency struct {
	archTag      string
	dependencies []string
}

var (
	// Linux386 platform description for Linux386
	Linux386 = PlatformDescription{Name: "linux/386", Arch: "i386", DefaultTag: "i386"}
	// LinuxAMD64 platform description for LinuxAMD64
	LinuxAMD64 = PlatformDescription{Name: "linux/amd64", Arch: "", DefaultTag: ""} // builders run on amd64 platform
	// LinuxARM64 platform description for LinuxARM64
	LinuxARM64 = PlatformDescription{Name: "linux/arm64", Arch: "arm64", DefaultTag: "arm64"}
	// LinuxARM5 platform description for LinuxARM5
	LinuxARM5 = PlatformDescription{Name: "linux/arm5", Arch: "armel", DefaultTag: "armel"}
	// LinuxARM6 platform description for LinuxARM6
	LinuxARM6 = PlatformDescription{Name: "linux/arm6", Arch: "armel", DefaultTag: "armel"}
	// LinuxARM7 platform description for LinuxARM7
	LinuxARM7 = PlatformDescription{Name: "linux/arm7", Arch: "armhf", DefaultTag: "armhf"}
	// LinuxMIPS platform description for LinuxMIPS
	LinuxMIPS = PlatformDescription{Name: "linux/mips", Arch: "mips", DefaultTag: "mips"}
	// LinuxMIPSLE platform description for LinuxMIPSLE
	LinuxMIPSLE = PlatformDescription{Name: "linux/mipsle", Arch: "mipsel", DefaultTag: "mipsel"}
	// LinuxMIPS64LE platform description for LinuxMIPS64LE
	LinuxMIPS64LE = PlatformDescription{Name: "linux/mips64le", Arch: "mips64el", DefaultTag: "mips64el"}
	// LinuxPPC64LE platform description for LinuxPPC64LE
	LinuxPPC64LE = PlatformDescription{Name: "linux/ppc64le", Arch: "ppc64el", DefaultTag: "ppc64el"}
	// LinuxS390x platform description for LinuxS390x
	LinuxS390x = PlatformDescription{Name: "linux/s390x", Arch: "s390x", DefaultTag: "s390x"}
)

// NewPackageInstaller instantiates the package
func NewPackageInstaller() *PackageInstaller {
	return &PackageInstaller{}
}

// AddEach function adds new package installer step
func (i *PackageInstaller) AddEach(ps []PlatformDescription, names ...string) *PackageInstaller {
	for _, p := range ps {
		i.Add(p, names...)
	}
	return i
}

// Add function adds new package
func (i *PackageInstaller) Add(p PlatformDescription, names ...string) *PackageInstaller {
	i.AddPackages(p, p.Packages(names...))
	return i
}

// AddPackages function adds a list of packages
func (i *PackageInstaller) AddPackages(p PlatformDescription, details ...PackageDependency) *PackageInstaller {
	if i.table == nil {
		i.table = map[PlatformDescription][]PackageDependency{}
	}
	i.table[p] = append(i.table[p], details...)
	return i
}

// Installer installs the package
func (i *PackageInstaller) Installer(name string) func() error {
	var platform PlatformDescription
	for p := range i.table {
		if p.Name == name {
			platform = p
		}
	}

	if platform.Name == "" {
		return func() error { return nil }
	}

	return func() error {
		return i.Install(platform)
	}
}

// Install function installs the package
func (i *PackageInstaller) Install(p PlatformDescription) error {
	packages := map[string]struct{}{}
	for _, details := range i.table[p] {
		for _, name := range details.List() {
			packages[name] = struct{}{}
		}
	}

	j, lst := 0, make([]string, len(packages))
	for name := range packages {
		lst[j], j = name, j+1
	}

	return installDependencies(p.Arch, lst...)
}

func installDependencies(arch string, pkgs ...string) error {
	if arch != "" {
		err := sh.Run("dpkg", "--add-architecture", arch)
		if err != nil {
			return fmt.Errorf("error while adding architecture: %w", err)
		}
	}

	if err := sh.Run("apt-get", "update"); err != nil {
		return err
	}

	params := append([]string{"install", "-y",
		"--no-install-recommends",

		// Journalbeat is built with old versions of Debian that don't update
		// their repositories, so they have expired keys.
		// Allow unauthenticated packages.
		// This was not enough: "-o", "Acquire::Check-Valid-Until=false",
		"--allow-unauthenticated",
	}, pkgs...)
	return sh.Run("apt-get", params...)
}

// Packages adds package dependencies
func (p PlatformDescription) Packages(names ...string) PackageDependency {
	return PackageDependency{}.WithTag(p.DefaultTag).Add(names...)
}

// Add adds package dependency
func (p PackageDependency) Add(deps ...string) PackageDependency {
	if len(deps) == 0 {
		return p
	}

	// always copy to ensure that we never share or overwrite slices due to capacity being too large
	p.dependencies = append(make([]string, 0, len(p.dependencies)+len(deps)), p.dependencies...)
	p.dependencies = append(p.dependencies, deps...)
	return p
}

// WithTag adds tag
func (p PackageDependency) WithTag(tag string) PackageDependency {
	p.archTag = tag
	return p
}

// List function lists dependencies
func (p PackageDependency) List() []string {
	if p.archTag == "" {
		return p.dependencies
	}

	names := make([]string, len(p.dependencies))
	for i, name := range p.dependencies {
		names[i] = fmt.Sprintf("%v:%v", name, p.archTag)
	}
	return names
}
