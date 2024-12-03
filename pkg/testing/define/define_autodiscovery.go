package define

import (
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"
)

// Default platforms. Overridable using InitAutodiscovery()
var defaultPlatforms = []TestPlatform{
	{OS: Windows, Arch: AMD64},

	// Not supported by default
	// {OS: Windows, Arch: ARM64},

	// Current batching mechanism support this, not sure it's correct
	{OS: Darwin, Arch: AMD64},
	{OS: Darwin, Arch: ARM64},
	{OS: Linux, Arch: AMD64},
	{OS: Linux, Arch: ARM64},
}

// k8s default platforms
// TODO this should be used for k8s tests ?
var k8sPlatforms = []TestPlatform{
	{OS: Kubernetes, Arch: AMD64},
	{OS: Kubernetes, Arch: ARM64},
}

var defaultTestOS = TestOS{
	Name:    "",
	Version: "",
}

var defaultTestPlatform = TestPlatform{
	OS:   "",
	Arch: "",
}

// YAML/JSON output structs
type OutputRunner struct {
	OSFamily string        `json:"os_family" yaml:"os_family" `
	Arch     string        `json:"arch,omitempty"`
	OS       string        `json:"os,omitempty"`
	Version  string        `json:"version,omitempty"`
	Groups   []OutputGroup `json:"groups,omitempty"`
}

type OutputGroup struct {
	Name  string
	Tests []OutputTest
}

type OutputTest struct {
	Name     string
	Metadata TestMetadata
}

// structs to aggregate test information
type TestPlatform struct {
	OS   string `json:"os" yaml:"os"`
	Arch string `json:"arch" yaml:"arch"`
}

type TestMetadata struct {
	Local bool `json:"local" yaml:"local"`
	Sudo  bool `json:"sudo" yaml:"sudo"`
}

type TestOS struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}
type TestGroup struct {
	Tests map[string]TestMetadata
}

func NewTestGroup() TestGroup {
	return TestGroup{
		Tests: map[string]TestMetadata{},
	}
}

type TestByOS struct {
	Groups map[string]TestGroup
}

func NewTestByOS() TestByOS {
	return TestByOS{
		Groups: map[string]TestGroup{},
	}
}

type TestsByPlatform struct {
	OperatingSystems map[TestOS]TestByOS `json:"os" yaml:"os"`
}

func NewTestsByPlatform() TestsByPlatform {
	return TestsByPlatform{OperatingSystems: map[TestOS]TestByOS{}}
}

type DiscoveredTests struct {
	Discovered map[TestPlatform]TestsByPlatform
}

// test autodiscovery aggregator
var testAutodiscovery *DiscoveredTests
var testAutodiscoveryMx sync.Mutex

type Named interface {
	Name() string
}

func InitAutodiscovery(initDefaultPlatforms []TestPlatform) {
	testAutodiscoveryMx.Lock()
	defer testAutodiscoveryMx.Unlock()
	testAutodiscovery = &DiscoveredTests{
		Discovered: map[TestPlatform]TestsByPlatform{},
	}

	if initDefaultPlatforms != nil {
		defaultPlatforms = initDefaultPlatforms
	}
}

func DumpAutodiscoveryYAML() ([]byte, error) {
	testAutodiscoveryMx.Lock()
	defer testAutodiscoveryMx.Unlock()
	err := testAutodiscovery.normalizeDiscoveredTests()
	if err != nil {
		return nil, fmt.Errorf("normalizing discovered tests: %w", err)
	}

	runners := mapToRunners(testAutodiscovery)

	return yaml.Marshal(runners)
}

func mapToRunners(autodiscovery *DiscoveredTests) []OutputRunner {

	var mapped []OutputRunner

	for pltf, testsByOS := range autodiscovery.Discovered {
		for testOS, testsByOS := range testsByOS.OperatingSystems {
			or := OutputRunner{
				OSFamily: pltf.OS,
				Arch:     pltf.Arch,
				OS:       testOS.Name,
				Version:  testOS.Version,
				Groups:   make([]OutputGroup, 0, len(testsByOS.Groups)),
			}

			for groupName, groupTests := range testsByOS.Groups {
				or.Groups = append(or.Groups, mapGroup(groupName, groupTests))
			}
			mapped = append(mapped, or)
		}
	}

	return mapped
}

func mapGroup(name string, group TestGroup) OutputGroup {
	og := OutputGroup{Name: name, Tests: make([]OutputTest, 0, len(group.Tests))}
	for testName, testMetadata := range group.Tests {
		og.Tests = append(og.Tests, OutputTest{
			Name:     testName,
			Metadata: testMetadata,
		})
	}

	return og
}

func discoverTest(test Named, reqs Requirements) {
	testAutodiscoveryMx.Lock()
	defer testAutodiscoveryMx.Unlock()
	for _, p := range getPlatforms(reqs.OS) {
		if testAutodiscovery == nil {
			panic("testAutodiscovery is nil. Check that InitAutodiscovery() has been called properly")
		}
		mappedOSesForPlatform := ensureMapping(testAutodiscovery.Discovered, p, NewTestsByPlatform)
		osForPlatform := getOSForPlatform(reqs.OS, p)
		for _, o := range osForPlatform {
			testsByOS := ensureMapping(mappedOSesForPlatform.OperatingSystems, o, NewTestByOS)
			testGroup := ensureMapping(testsByOS.Groups, reqs.Group, NewTestGroup)
			testGroup.Tests[test.Name()] = TestMetadata{
				Local: reqs.Local,
				Sudo:  reqs.Sudo,
			}
		}
	}
}

func ensureMapping[K comparable, V any](mappings map[K]V, k K, newValueCreateFunc func() V) V {
	if existingValue, ok := mappings[k]; ok {
		return existingValue
	}
	newValue := newValueCreateFunc()
	mappings[k] = newValue
	return newValue
}

func getOSForPlatform(os []OS, p TestPlatform) []TestOS {

	var matchingOSes []TestOS

	for _, o := range os {
		if o.Type == p.OS && o.Arch == p.Arch {
			matchingOSes = append(matchingOSes, getTestOS(o))
		}
	}

	if len(matchingOSes) > 0 {
		return matchingOSes
	}

	// no other OS has matched, return the default OS
	return []TestOS{
		defaultTestOS,
	}

}

func getTestOS(o OS) TestOS {
	switch {
	case o.Type == Linux:
		return TestOS{
			Name:    o.Distro,
			Version: o.Version,
		}
	default:
		return TestOS{
			Name:    o.Type,
			Version: o.Version,
		}
	}
}

func getPlatforms(os []OS) []TestPlatform {
	if len(os) == 0 {
		return []TestPlatform{defaultTestPlatform}
	}

	platforms := make([]TestPlatform, 0, len(os))
	for _, o := range os {
		platforms = append(platforms, TestPlatform{
			OS:   o.Type,
			Arch: o.Arch,
		})
	}

	return platforms
}

// Normalization functions
func (dt *DiscoveredTests) normalizeDiscoveredTests() error {

	normalized := map[TestPlatform]TestsByPlatform{}
	for pltf, oses := range dt.Discovered {

		if pltf.OS == "" && pltf.Arch != "" {
			return fmt.Errorf("platform not supported: %v", pltf)
		}

		if pltf.OS != "" && pltf.Arch != "" {
			existingOSes := ensureMapping(normalized, pltf, NewTestsByPlatform) // normal case, append to normalized and go to the next platform
			existingOSes.mergeOSes(oses)
			continue
		}

		// Arch and/or OS is not specified: fill in the supported archs for the OS type (potentially for all OSes)
		for i, dp := range defaultPlatforms {
			if pltf.OS == "" || pltf.OS == dp.OS {
				existingOSes := ensureMapping(normalized, defaultPlatforms[i], NewTestsByPlatform)
				existingOSes.mergeOSes(oses)
			}
		}
	}

	dt.Discovered = normalized

	return nil
}

func (tbp *TestsByPlatform) mergeOSes(from TestsByPlatform) {
	for testOS, testsByOS := range from.OperatingSystems {
		// iterate over all the OS definitions, ensuring that the entry exists in the destination map
		existingTestsByOS := ensureMapping(tbp.OperatingSystems, testOS, NewTestByOS)
		// iterate over source groups for this OS and merge
		for grp, tests := range testsByOS.Groups {
			// iterate over all the OS definitions, ensuring that the entry exists in the destination map
			existingGroup := ensureMapping(existingTestsByOS.Groups, grp, NewTestGroup)
			// add all the tests
			for testName, testMeta := range tests.Tests {
				existingGroup.Tests[testName] = testMeta
			}
		}
	}
}
