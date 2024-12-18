// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package packaging

// This file contains tests that can be run on the generated packages.
// To run these tests use `go test package_test.go`.

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/blakesmith/ar"
	"github.com/cavaliergopher/rpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/dev-tools/mage"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
)

const (
	expectedConfigMode     = os.FileMode(0600)
	expectedManifestMode   = os.FileMode(0644)
	expectedModuleFileMode = expectedManifestMode
	expectedModuleDirMode  = os.FileMode(0755)

	rootUser = "root"
)

var (
	excludedPathsPattern    = regexp.MustCompile(`node_modules`)
	configFilePattern       = regexp.MustCompile(`.*beat\.spec.yml$|.*beat\.yml$|apm-server\.yml|elastic-agent\.yml$$`)
	manifestFilePattern     = regexp.MustCompile(`manifest.yml`)
	modulesDirPattern       = regexp.MustCompile(`module/.+`)
	modulesDDirPattern      = regexp.MustCompile(`modules.d/$`)
	modulesDFilePattern     = regexp.MustCompile(`modules.d/.+`)
	monitorsDFilePattern    = regexp.MustCompile(`monitors.d/.+`)
	systemdUnitFilePattern  = regexp.MustCompile(`/lib/systemd/system/.*\.service`)
	hintsInputsDFilePattern = regexp.MustCompile(`usr/share/elastic-agent/hints.inputs.d/.*\.yml`)

	licenseFiles = []string{"LICENSE.txt", "NOTICE.txt"}
)

var (
	files             = flag.String("files", "../build/distributions/*/*", "filepath glob containing package files")
	modules           = flag.Bool("modules", false, "check modules folder contents")
	minModules        = flag.Int("min-modules", 4, "minimum number of modules to expect in modules folder")
	modulesd          = flag.Bool("modules.d", false, "check modules.d folder contents")
	monitorsd         = flag.Bool("monitors.d", false, "check monitors.d folder contents")
	rootOwner         = flag.Bool("root-owner", false, "expect root to own package files")
	rootUserContainer = flag.Bool("root-user-container", false, "expect root in container user")
)

func TestRPM(t *testing.T) {
	rpms := getFiles(t, regexp.MustCompile(`\.rpm$`))
	for _, rpm := range rpms {
		checkRPM(t, rpm)
	}
}

func TestDeb(t *testing.T) {
	debs := getFiles(t, regexp.MustCompile(`\.deb$`))
	buf := new(bytes.Buffer)
	for _, deb := range debs {
		checkDeb(t, deb, buf)
	}
}

func TestTar(t *testing.T) {
	// Regexp matches *-arch.tar.gz, but not *-arch.docker.tar.gz
	tars := getFiles(t, regexp.MustCompile(`-\w+\.tar\.gz$`))
	for _, tar := range tars {
		checkTar(t, tar)
	}
}

func TestZip(t *testing.T) {
	zips := getFiles(t, regexp.MustCompile(`^\w+\S+.zip$`))
	for _, zip := range zips {
		checkZip(t, zip)
	}
}

func TestDocker(t *testing.T) {
	dockers := getFiles(t, regexp.MustCompile(`\.docker\.tar\.gz$`))
	for _, docker := range dockers {
		t.Log(docker)
		checkDocker(t, docker)
	}
}

// Sub-tests

func checkRPM(t *testing.T, file string) {
	p, _, err := readRPM(file)
	if err != nil {
		t.Error(err)
		return
	}

	checkConfigPermissions(t, p)
	checkConfigOwner(t, p, *rootOwner)
	checkManifestPermissions(t, p)
	checkManifestOwner(t, p, *rootOwner)
	checkModulesOwner(t, p, *rootOwner)
	checkModulesPermissions(t, p)
	checkModulesPresent(t, "/usr/share", p)
	checkModulesDPresent(t, "/etc/", p)
	checkMonitorsDPresent(t, "/etc", p)
	checkLicensesPresent(t, "/usr/share", p)
	checkSystemdUnitPermissions(t, p)
	ensureNoBuildIDLinks(t, p)
}

func checkDeb(t *testing.T, file string, buf *bytes.Buffer) {
	p, err := readDeb(file, buf)
	if err != nil {
		t.Error(err)
		return
	}

	// deb file permissions are managed post-install
	checkConfigPermissions(t, p)
	checkConfigOwner(t, p, true)
	checkManifestPermissions(t, p)
	checkManifestOwner(t, p, true)
	checkModulesPresent(t, "./usr/share", p)
	checkModulesDPresent(t, "./etc/", p)
	checkMonitorsDPresent(t, "./etc/", p)
	checkLicensesPresent(t, "./usr/share", p)
	checkModulesOwner(t, p, true)
	checkModulesPermissions(t, p)
	checkSystemdUnitPermissions(t, p)
}

func checkTar(t *testing.T, file string) {
	p, err := readTar(file)
	if err != nil {
		t.Error(err)
		return
	}

	checkConfigPermissions(t, p)
	checkConfigOwner(t, p, true)
	checkManifestPermissions(t, p)
	checkModulesPresent(t, "", p)
	checkModulesDPresent(t, "", p)
	checkModulesPermissions(t, p)
	checkModulesOwner(t, p, true)
	checkLicensesPresent(t, "", p)

	t.Run(p.Name+"_check_manifest_file", func(t *testing.T) {
		tempExtractionPath := t.TempDir()
		err = mage.Extract(file, tempExtractionPath)
		require.NoError(t, err, "error extracting tar archive")
		containingDir := strings.TrimSuffix(path.Base(file), ".tar.gz")
		checkManifestFileContents(t, filepath.Join(tempExtractionPath, containingDir))
	})

	checkSha512PackageHash(t, file)
}

func checkZip(t *testing.T, file string) {
	p, err := readZip(t, file, checkNpcapNotices)
	if err != nil {
		t.Error(err)
		return
	}

	checkConfigPermissions(t, p)
	checkManifestPermissions(t, p)
	checkModulesPresent(t, "", p)
	checkModulesDPresent(t, "", p)
	checkModulesPermissions(t, p)
	checkLicensesPresent(t, "", p)

	t.Run(p.Name+"_check_manifest_file", func(t *testing.T) {
		tempExtractionPath := t.TempDir()
		err = mage.Extract(file, tempExtractionPath)
		require.NoError(t, err, "error extracting zip archive")
		containingDir := strings.TrimSuffix(path.Base(file), ".zip")
		checkManifestFileContents(t, filepath.Join(tempExtractionPath, containingDir))
	})

	checkSha512PackageHash(t, file)
}

func checkManifestFileContents(t *testing.T, extractedPackageDir string) {
	t.Log("Checking file manifest.yaml")
	manifestReadCloser, err := os.Open(filepath.Join(extractedPackageDir, v1.ManifestFileName))
	if err != nil {
		t.Errorf("opening manifest %s : %v", v1.ManifestFileName, err)
	}
	defer func(closer io.ReadCloser) {
		err := closer.Close()
		assert.NoError(t, err, "error closing manifest file")
	}(manifestReadCloser)

	var m v1.PackageManifest
	err = yaml.NewDecoder(manifestReadCloser).Decode(&m)
	if err != nil {
		t.Errorf("unmarshaling package manifest: %v", err)
	}

	assert.Equal(t, v1.ManifestKind, m.Kind, "manifest specifies wrong kind")
	assert.Equal(t, v1.VERSION, m.Version, "manifest specifies wrong api version")

	assert.NotEmpty(t, m.Package.Version, "manifest version must not be empty")
	assert.NotEmpty(t, m.Package.Hash, "manifest hash must not be empty")

	if assert.NotEmpty(t, m.Package.PathMappings, "path mappings in manifest are empty") {
		versionedHome := m.Package.VersionedHome
		assert.DirExistsf(t, filepath.Join(extractedPackageDir, versionedHome), "versionedHome directory %q not found in %q", versionedHome, extractedPackageDir)
		if assert.Contains(t, m.Package.PathMappings[0], versionedHome, "path mappings in manifest do not contain the extraction path for versionedHome") {
			// the first map should have the mapping for the data/elastic-agent-****** path)
			mappedPath := m.Package.PathMappings[0][versionedHome]
			assert.Contains(t, mappedPath, m.Package.Version, "mapped path for versionedHome does not contain the package version")
			if m.Package.Snapshot {
				assert.Contains(t, mappedPath, "SNAPSHOT", "mapped path for versionedHome does not contain the snapshot qualifier")
			}
		}
	}
}

const (
	npcapLicense    = `Dependency : Npcap \(https://nmap.org/npcap/\)`
	libpcapLicense  = `Dependency : Libpcap \(http://www.tcpdump.org/\)`
	winpcapLicense  = `Dependency : Winpcap \(https://www.winpcap.org/\)`
	radiotapLicense = `Dependency : ieee80211_radiotap.h Header File`
)

// This reflects the order that the licenses and notices appear in the relevant files.
var npcapLicensePattern = regexp.MustCompile(
	"(?s)" + npcapLicense +
		".*" + libpcapLicense +
		".*" + winpcapLicense +
		".*" + radiotapLicense,
)

func checkNpcapNotices(pkg, file string, contents io.Reader) error {
	if !strings.Contains(pkg, "packetbeat") {
		return nil
	}

	wantNotices := strings.Contains(pkg, "windows") && !strings.Contains(pkg, "oss")

	// If the packetbeat README.md is made to be generated
	// conditionally then it should also be checked here.
	pkg = filepath.Base(pkg)
	file, err := filepath.Rel(pkg[:len(pkg)-len(filepath.Ext(pkg))], file)
	if err != nil {
		return err
	}
	switch file {
	case "NOTICE.txt":
		if npcapLicensePattern.MatchReader(bufio.NewReader(contents)) != wantNotices {
			if wantNotices {
				return fmt.Errorf("Npcap license section not found in %s file in %s", file, pkg)
			}
			return fmt.Errorf("unexpected Npcap license section found in %s file in %s", file, pkg)
		}
	}
	return nil
}

func checkDocker(t *testing.T, file string) {
	p, info, err := readDocker(file)
	if err != nil {
		t.Errorf("error reading file %v: %v", file, err)
		return
	}

	checkDockerEntryPoint(t, p, info)
	checkDockerLabels(t, p, info, file)
	checkDockerUser(t, p, info, *rootUserContainer)
	checkConfigPermissionsWithMode(t, p, configFilePattern, os.FileMode(0644))
	checkManifestPermissionsWithMode(t, p, os.FileMode(0644))
	checkModulesPresent(t, "", p)
	checkModulesDPresent(t, "", p)
	checkHintsInputsD(t, "hints.inputs.d", hintsInputsDFilePattern, p)
	checkLicensesPresent(t, "licenses/", p)
}

// Verify that the main configuration file is installed with a 0600 file mode.
func checkConfigPermissions(t *testing.T, p *packageFile) {
	checkConfigPermissionsWithMode(t, p, configFilePattern, expectedConfigMode)
}

func checkConfigPermissionsWithMode(t *testing.T, p *packageFile, configPattern *regexp.Regexp, expectedMode os.FileMode) {
	t.Run(p.Name+" config file permissions", func(t *testing.T) {
		for _, entry := range p.Contents {
			if configPattern.MatchString(entry.File) {
				mode := entry.Mode.Perm()
				if expectedMode != mode {
					t.Errorf("file %v has wrong permissions: expected=%v actual=%v",
						entry.File, expectedMode, mode)
				}
				return
			}
		}
		t.Errorf("no config file found matching %v", configPattern)
	})
}

func checkOwner(t *testing.T, entry packageEntry, expectRoot bool) {
	should := "not "
	if expectRoot {
		should = ""
	}
	if expectRoot != (entry.UID == 0) {
		t.Errorf("file %v should %sbe owned by root user, owner=%v", entry.File, should, entry.UID)
	}
	if expectRoot != (entry.GID == 0) {
		t.Errorf("file %v should %sbe owned by root group, group=%v", entry.File, should, entry.GID)
	}
}

func checkConfigOwner(t *testing.T, p *packageFile, expectRoot bool) {
	t.Run(p.Name+" config file owner", func(t *testing.T) {
		for _, entry := range p.Contents {
			if configFilePattern.MatchString(entry.File) {
				checkOwner(t, entry, expectRoot)
				return
			}
		}
		t.Errorf("no config file found matching %v", configFilePattern)
	})
}

// Verify that the modules manifest.yml files are installed with a 0644 file mode.
func checkManifestPermissions(t *testing.T, p *packageFile) {
	checkManifestPermissionsWithMode(t, p, expectedManifestMode)
}

func checkManifestPermissionsWithMode(t *testing.T, p *packageFile, expectedMode os.FileMode) {
	t.Run(p.Name+" manifest file permissions", func(t *testing.T) {
		for _, entry := range p.Contents {
			if manifestFilePattern.MatchString(entry.File) {
				mode := entry.Mode.Perm()
				if expectedMode != mode {
					t.Errorf("file %v has wrong permissions: expected=%v actual=%v",
						entry.File, expectedMode, mode)
				}
			}
		}
	})
}

// Verify that the manifest owner is correct.
func checkManifestOwner(t *testing.T, p *packageFile, expectRoot bool) {
	t.Run(p.Name+" manifest file owner", func(t *testing.T) {
		for _, entry := range p.Contents {
			if manifestFilePattern.MatchString(entry.File) {
				checkOwner(t, entry, expectRoot)
			}
		}
	})
}

// Verify the permissions of the modules.d dir and its contents.
func checkModulesPermissions(t *testing.T, p *packageFile) {
	t.Run(p.Name+" modules.d file permissions", func(t *testing.T) {
		for _, entry := range p.Contents {
			if modulesDFilePattern.MatchString(entry.File) {
				mode := entry.Mode.Perm()
				if expectedModuleFileMode != mode {
					t.Errorf("file %v has wrong permissions: expected=%v actual=%v",
						entry.File, expectedModuleFileMode, mode)
				}
			} else if modulesDDirPattern.MatchString(entry.File) {
				mode := entry.Mode.Perm()
				if expectedModuleDirMode != mode {
					t.Errorf("file %v has wrong permissions: expected=%v actual=%v",
						entry.File, expectedModuleDirMode, mode)
				}
			}
		}
	})
}

// Verify the owner of the modules.d dir and its contents.
func checkModulesOwner(t *testing.T, p *packageFile, expectRoot bool) {
	t.Run(p.Name+" modules.d file owner", func(t *testing.T) {
		for _, entry := range p.Contents {
			if modulesDFilePattern.MatchString(entry.File) || modulesDDirPattern.MatchString(entry.File) {
				checkOwner(t, entry, expectRoot)
			}
		}
	})
}

// Verify that the systemd unit file has a mode of 0644. It should not be
// executable.
func checkSystemdUnitPermissions(t *testing.T, p *packageFile) {
	const expectedMode = os.FileMode(0644)
	t.Run(p.Name+" systemd unit file permissions", func(t *testing.T) {
		for _, entry := range p.Contents {
			if systemdUnitFilePattern.MatchString(entry.File) {
				mode := entry.Mode.Perm()
				if expectedMode != mode {
					t.Errorf("file %v has wrong permissions: expected=%v actual=%v",
						entry.File, expectedMode, mode)
				}
				return
			}
		}
		t.Errorf("no systemd unit file found matching %v", configFilePattern)
	})
}

// Verify that modules folder is present and has module files in
func checkModulesPresent(t *testing.T, prefix string, p *packageFile) {
	if *modules {
		checkModules(t, "modules", prefix, modulesDirPattern, p)
	}
}

// Verify that modules.d folder is present and has module files in
func checkModulesDPresent(t *testing.T, prefix string, p *packageFile) {
	if *modulesd {
		checkModules(t, "modules.d", prefix, modulesDFilePattern, p)
	}
}

func checkMonitorsDPresent(t *testing.T, prefix string, p *packageFile) {
	if *monitorsd {
		checkMonitors(t, "monitors.d", prefix, monitorsDFilePattern, p)
	}
}

func checkHintsInputsD(t *testing.T, name string, r *regexp.Regexp, p *packageFile) {
	t.Run(fmt.Sprintf("%s %s contents", p.Name, name), func(t *testing.T) {
		total := 0
		for _, entry := range p.Contents {
			if r.MatchString(entry.File) {
				total++
			}
		}

		if total == 0 {
			t.Errorf("no hints inputs found under %s", name)
		}
	})
}

func checkModules(t *testing.T, name, prefix string, r *regexp.Regexp, p *packageFile) {
	t.Run(fmt.Sprintf("%s %s contents", p.Name, name), func(t *testing.T) {
		minExpectedModules := *minModules
		total := 0
		for _, entry := range p.Contents {
			if strings.HasPrefix(entry.File, prefix) && r.MatchString(entry.File) {
				total++
			}
		}

		if total < minExpectedModules {
			t.Errorf("not enough modules found under %s: actual=%d, expected>=%d",
				name, total, minExpectedModules)
		}
	})
}

func checkMonitors(t *testing.T, name, prefix string, r *regexp.Regexp, p *packageFile) {
	t.Run(fmt.Sprintf("%s %s contents", p.Name, name), func(t *testing.T) {
		minExpectedModules := 1
		total := 0
		for _, entry := range p.Contents {
			if strings.HasPrefix(entry.File, prefix) && r.MatchString(entry.File) {
				total++
			}
		}

		if total < minExpectedModules {
			t.Errorf("not enough monitors found under %s: actual=%d, expected>=%d",
				name, total, minExpectedModules)
		}
	})
}

func checkLicensesPresent(t *testing.T, prefix string, p *packageFile) {
	for _, licenseFile := range licenseFiles {
		t.Run("License file "+licenseFile, func(t *testing.T) {
			for _, entry := range p.Contents {
				if strings.HasPrefix(entry.File, prefix) && strings.HasSuffix(entry.File, "/"+licenseFile) {
					return
				}
			}
			if prefix != "" {
				t.Fatalf("not found under %s", prefix)
			}
			t.Fatal("not found")
		})
	}
}

func checkDockerEntryPoint(t *testing.T, p *packageFile, info *dockerInfo) {
	expectedMode := os.FileMode(0755)

	t.Run(fmt.Sprintf("%s entrypoint", p.Name), func(t *testing.T) {
		if len(info.Config.Entrypoint) == 0 {
			t.Fatal("no entrypoint")
		}

		entrypoint := info.Config.Entrypoint[0]
		if strings.HasPrefix(entrypoint, "/") {
			entrypoint := strings.TrimPrefix(entrypoint, "/")
			entry, found := p.Contents[entrypoint]
			if !found {
				t.Fatalf("%s entrypoint not found in docker", entrypoint)
			}
			if mode := entry.Mode.Perm(); mode != expectedMode {
				t.Fatalf("%s entrypoint mode is %s, expected: %s", entrypoint, mode, expectedMode)
			}
		} else {
			t.Fatal("TODO: check if binary is in $PATH")
		}
	})
}

func checkDockerLabels(t *testing.T, p *packageFile, info *dockerInfo, file string) {
	vendor := info.Config.Labels["org.label-schema.vendor"]
	if vendor != "Elastic" {
		return
	}

	t.Run(fmt.Sprintf("%s license labels", p.Name), func(t *testing.T) {
		expectedLicense := "Elastic License"
		ossPrefix := strings.Join([]string{
			info.Config.Labels["org.label-schema.name"],
			"oss",
			info.Config.Labels["org.label-schema.version"],
		}, "-")
		if strings.HasPrefix(filepath.Base(file), ossPrefix) {
			expectedLicense = "ASL 2.0"
		}
		licenseLabels := []string{
			"license",
			"org.label-schema.license",
		}
		for _, licenseLabel := range licenseLabels {
			if license, present := info.Config.Labels[licenseLabel]; !present || license != expectedLicense {
				t.Errorf("unexpected license label %s: %s", licenseLabel, license)
			}
		}
	})

	t.Run(fmt.Sprintf("%s required labels", p.Name), func(t *testing.T) {
		// From https://redhat-connect.gitbook.io/partner-guide-for-red-hat-openshift-and-container/program-on-boarding/technical-prerequisites
		requiredLabels := []string{"name", "vendor", "version", "release", "summary", "description"}
		for _, label := range requiredLabels {
			if value, present := info.Config.Labels[label]; !present || value == "" {
				t.Errorf("missing required label %s", label)
			}
		}
	})
}

func checkDockerUser(t *testing.T, p *packageFile, info *dockerInfo, expectRoot bool) {
	t.Run(fmt.Sprintf("%s user", p.Name), func(t *testing.T) {
		if expectRoot != (info.Config.User == rootUser) {
			t.Errorf("unexpected docker user: %s", info.Config.User)
		}
	})
}

// ensureNoBuildIDLinks checks for regressions related to
// https://github.com/elastic/beats/issues/12956.
func ensureNoBuildIDLinks(t *testing.T, p *packageFile) {
	t.Run(fmt.Sprintf("%s no build_id links", p.Name), func(t *testing.T) {
		for name := range p.Contents {
			if strings.Contains(name, "/usr/lib/.build-id") {
				t.Error("found unexpected /usr/lib/.build-id in package")
			}
		}
	})
}

// Helpers

type packageFile struct {
	Name     string
	Contents map[string]packageEntry
}

type packageEntry struct {
	File string
	UID  int
	GID  int
	Mode os.FileMode
}

func getFiles(t *testing.T, pattern *regexp.Regexp) []string {
	matches, err := filepath.Glob(*files)
	if err != nil {
		t.Fatal(err)
	}

	files := matches[:0]
	for _, f := range matches {
		if pattern.MatchString(filepath.Base(f)) {
			files = append(files, f)
		}
	}
	return files
}

func readRPM(rpmFile string) (*packageFile, *rpm.Package, error) {
	p, err := rpm.Open(rpmFile)
	if err != nil {
		return nil, nil, err
	}

	contents := p.Files()
	pf := &packageFile{Name: filepath.Base(rpmFile), Contents: map[string]packageEntry{}}

	for _, file := range contents {
		if excludedPathsPattern.MatchString(file.Name()) {
			continue
		}
		pe := packageEntry{
			File: file.Name(),
			Mode: file.Mode(),
		}
		if file.Owner() != rootUser {
			// not 0
			pe.UID = 123
			pe.GID = 123
		}
		pf.Contents[file.Name()] = pe
	}

	return pf, p, nil
}

// readDeb reads the data.tar.gz file from the .deb.
func readDeb(debFile string, dataBuffer *bytes.Buffer) (*packageFile, error) {
	file, err := os.Open(debFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	arReader := ar.NewReader(file)
	for {
		header, err := arReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		if strings.HasPrefix(header.Name, "data.tar.gz") {
			dataBuffer.Reset()
			_, err := io.Copy(dataBuffer, arReader)
			if err != nil {
				return nil, err
			}

			gz, err := gzip.NewReader(dataBuffer)
			if err != nil {
				return nil, err
			}
			defer gz.Close()

			return readTarContents(filepath.Base(debFile), gz)
		}
	}

	return nil, io.EOF
}

func readTar(tarFile string) (*packageFile, error) {
	file, err := os.Open(tarFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var fileReader io.ReadCloser = file
	if strings.HasSuffix(tarFile, ".gz") {
		if fileReader, err = gzip.NewReader(file); err != nil {
			return nil, err
		}
		defer fileReader.Close()
	}

	return readTarContents(filepath.Base(tarFile), fileReader)
}

func readTarContents(tarName string, data io.Reader) (*packageFile, error) {
	tarReader := tar.NewReader(data)

	p := &packageFile{Name: tarName, Contents: map[string]packageEntry{}}
	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if excludedPathsPattern.MatchString(header.Name) {
			continue
		}
		p.Contents[header.Name] = packageEntry{
			File: header.Name,
			UID:  header.Uid,
			GID:  header.Gid,
			Mode: os.FileMode(header.Mode),
		}
	}

	return p, nil
}

// inspector is a file contents inspector. It vets the contents of the file
// within a package for a requirement and returns an error if it is not met.
type inspector func(pkg, file string, contents io.Reader) error

func readZip(t *testing.T, zipFile string, inspectors ...inspector) (*packageFile, error) {
	r, err := openZip(zipFile)
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}
	defer r.Close()

	p := &packageFile{Name: filepath.Base(zipFile), Contents: map[string]packageEntry{}}
	for _, f := range r.File {
		if excludedPathsPattern.MatchString(f.Name) {
			continue
		}
		p.Contents[f.Name] = packageEntry{
			File: f.Name,
			Mode: f.Mode(),
		}
		for _, inspect := range inspectors {
			r, err := f.Open()
			if err != nil {
				t.Errorf("failed to open %s in %s: %v", f.Name, zipFile, err)
				break
			}
			err = inspect(zipFile, f.Name, r)
			if err != nil {
				t.Error(err)
			}
			r.Close()
		}
	}

	return p, nil
}

func openZip(zipFile string) (*zip.ReadCloser, error) {
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func readDocker(dockerFile string) (*packageFile, *dockerInfo, error) {
	// Read the manifest file first so that the config file and layer
	// names are known in advance.
	manifest, err := getDockerManifest(dockerFile)
	if err != nil {
		return nil, nil, err
	}

	file, err := os.Open(dockerFile)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	var info *dockerInfo
	layers := make(map[string]*packageFile)

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, nil, err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, nil, err
		}

		switch {
		case header.Name == manifest.Config:
			info, err = readDockerInfo(tarReader)
			if err != nil {
				return nil, nil, err
			}
		case slices.Contains(manifest.Layers, header.Name):
			layer, err := readTarContents(header.Name, tarReader)
			if err != nil {
				return nil, nil, err
			}
			layers[header.Name] = layer
		}
	}

	if len(info.Config.Entrypoint) == 0 {
		return nil, nil, fmt.Errorf("no entrypoint")
	}

	workingDir := info.Config.WorkingDir
	entrypoint := info.Config.Entrypoint[0]

	// Read layers in order and for each file keep only the entry seen in the later layer
	p := &packageFile{Name: filepath.Base(dockerFile), Contents: map[string]packageEntry{}}
	for _, layer := range manifest.Layers {
		layerFile, found := layers[layer]
		if !found {
			return nil, nil, fmt.Errorf("layer not found: %s", layer)
		}
		for name, entry := range layerFile.Contents {
			if excludedPathsPattern.MatchString(name) {
				continue
			}
			// Check only files in working dir and entrypoint
			if strings.HasPrefix("/"+name, workingDir) || "/"+name == entrypoint {
				p.Contents[name] = entry
			}
			// Add also licenses
			for _, licenseFile := range licenseFiles {
				if strings.Contains(name, licenseFile) {
					p.Contents[name] = entry
				}
			}
		}
	}

	if len(p.Contents) == 0 {
		return nil, nil, fmt.Errorf("no files found in docker working directory (%s)", info.Config.WorkingDir)
	}

	return p, info, nil
}

type dockerManifest struct {
	Config   string
	RepoTags []string
	Layers   []string
}

type dockerInfo struct {
	Config struct {
		Entrypoint []string
		Labels     map[string]string
		User       string
		WorkingDir string
	} `json:"config"`
}

func readDockerInfo(r io.Reader) (*dockerInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var info dockerInfo
	err = json.Unmarshal(data, &info)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

// getDockerManifest opens a gzipped tar file to read the Docker manifest.json
// that it is expected to contain.
func getDockerManifest(file string) (*dockerManifest, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gzipReader, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	var manifest *dockerManifest
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		if header.Name == "manifest.json" {
			manifest, err = readDockerManifest(tarReader)
			if err != nil {
				return nil, err
			}
			break
		}
	}

	return manifest, nil
}

func readDockerManifest(r io.Reader) (*dockerManifest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var manifests []*dockerManifest
	err = json.Unmarshal(data, &manifests)
	if err != nil {
		return nil, err
	}

	if len(manifests) != 1 {
		return nil, fmt.Errorf("one and only one manifest expected, %d found", len(manifests))
	}

	return manifests[0], nil
}

func checkSha512PackageHash(t *testing.T, packageFile string) {
	t.Run("check hash file", func(t *testing.T) {
		expectedHashFile := packageFile + ".sha512"
		require.FileExists(t, expectedHashFile, "hash file for package %q should exist with name %q", packageFile, expectedHashFile)

		// calculate SHA512 hash for the file
		hashFile, err := os.Open(expectedHashFile)
		require.NoError(t, err, "hash file should be readable")

		checksumsMap := readHashFile(t, hashFile)

		packageBaseName := filepath.Base(packageFile)
		require.Containsf(t, checksumsMap, packageBaseName, "checksum file should contain an entry for %q", packageBaseName)

		// compare checksum entry with actual package hash
		checksum := calculateChecksum(t, packageFile, sha512.New())

		assert.Equalf(t, checksum, checksumsMap[packageBaseName], "checksum for file %q does not match", packageFile)
	})
}

func calculateChecksum(t *testing.T, file string, hasher hash.Hash) string {

	input, err := os.Open(file)
	require.NoErrorf(t, err, "error opening input file %q", file)

	defer func(input *os.File) {
		errClose := input.Close()
		assert.NoErrorf(t, errClose, "error closing input file %q", file)
	}(input)

	_, err = io.Copy(hasher, input)
	require.NoError(t, err, "error reading file to calculate hash")

	return hex.EncodeToString(hasher.Sum(nil))
}

// readHashFile return a map of {filename, hash} reading a .sha512 file.
// If any line has not exactly 2 tokens separated by white spaces, it will fail the test.
// When it's done reading it will close the reader
func readHashFile(t *testing.T, reader io.ReadCloser) map[string]string {

	defer func(reader io.ReadCloser) {
		err := reader.Close()
		assert.NoError(t, err, "error closing hash file reader")
	}(reader)

	checksums := map[string]string{}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) != 2 {
			// Fail test because it's malformed.
			assert.Failf(t, "malformed line %q in hash file", line)
			continue
		}
		filename := strings.TrimLeft(parts[1], "*")
		checksum := parts[0]
		checksums[filename] = checksum
	}

	return checksums
}
