package define

import (
	"fmt"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type TestPlatform struct {
	OS   string
	Arch string
}

func (tp *TestPlatform) String() string {
	return fmt.Sprintf("%s/%s", tp.OS, tp.Arch)
}

func (tp *TestPlatform) Parse(s string) error {
	var ok bool
	tp.OS, tp.Arch, ok = strings.Cut(s, "/")
	if !ok {
		return fmt.Errorf("separator not found in platform string %q", s)
	}
	return nil
}

func (tp *TestPlatform) MarshalYAML() (interface{}, error) {
	return tp.String(), nil
}

type TestMetadata struct {
	Name  string `json:"-" yaml:"-"`
	Local bool   `json:"local" yaml:"local"`
	Sudo  bool   `json:"sudo" yaml:"sudo"`
}

type TestOS struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}

type TestGroup struct {
	Name  string                  `json:"-" yaml:"-"`
	Tests map[string]TestMetadata `json:"tests" yaml:"tests"`
}

func NewTestGroup(groupName string) TestGroup {
	return TestGroup{
		Name:  groupName,
		Tests: map[string]TestMetadata{},
	}
}

type TestByOS struct {
	OperatingSystem TestOS               `json:"-" yaml:"-"`
	Groups          map[string]TestGroup `json:"groups" yaml:"groups"`
}

func NewTestByOS(tos TestOS) TestByOS {
	return TestByOS{
		OperatingSystem: tos,
		Groups:          map[string]TestGroup{},
	}
}

type TestsByPlatform struct {
	Platform         TestPlatform        `json:"-" yaml:"-"`
	OperatingSystems map[TestOS]TestByOS `json:"os" yaml:"os"`
}

func NewTestsByPlatform(platform TestPlatform) TestsByPlatform {
	return TestsByPlatform{Platform: platform, OperatingSystems: map[TestOS]TestByOS{}}
}

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

// TODO this should be used for k8s tests ?
var k8sPlatforms = []TestPlatform{
	{OS: Kubernetes, Arch: AMD64},
	{OS: Kubernetes, Arch: ARM64},
}

var testAutodiscovery = map[TestPlatform]TestsByPlatform{}
var testAutodiscoveryMx sync.Mutex

type Named interface {
	Name() string
}

func InitAutodiscovery(initDefaultPlatforms []TestPlatform) {
	testAutodiscoveryMx.Lock()
	defer testAutodiscoveryMx.Unlock()
	testAutodiscovery = map[TestPlatform]TestsByPlatform{}

	if initDefaultPlatforms != nil {
		defaultPlatforms = initDefaultPlatforms
	}
}

func DumpAutodiscoveryYAML() ([]byte, error) {
	testAutodiscoveryMx.Lock()
	defer testAutodiscoveryMx.Unlock()
	return yaml.Marshal(testAutodiscovery)
}

func discoverTest(test Named, reqs *Requirements) {
	testAutodiscoveryMx.Lock()
	defer testAutodiscoveryMx.Unlock()
	for _, p := range getPlatforms(reqs.OS) {
		mappedOSesForPlatform := ensureMapping(testAutodiscovery, p, NewTestsByPlatform)
		osForPlatform := getOSForPlatform(reqs.OS, p)
		for _, o := range osForPlatform {
			testsByOS := ensureMapping(mappedOSesForPlatform.OperatingSystems, o, NewTestByOS)
			testGroup := ensureMapping(testsByOS.Groups, reqs.Group, NewTestGroup)
			testGroup.Tests[test.Name()] = TestMetadata{
				Name:  test.Name(),
				Local: reqs.Local,
				Sudo:  reqs.Sudo,
			}
		}
	}
}

func ensureMapping[K comparable, V any](mappings map[K]V, k K, newValueCreateFunc func(K) V) V {
	if existingValue, ok := mappings[k]; ok {
		return existingValue
	}
	newValue := newValueCreateFunc(k)
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
		{
			Name:    "",
			Version: "",
		},
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
		return defaultPlatforms
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

// TODO
func normalizePlatforms(platforms []TestPlatform) ([]TestPlatform, error) {
	// check if there's just an os type without arch and normalize
	normalized := make([]TestPlatform, 0, len(platforms))
	for _, p := range platforms {
		if p.OS != "" && p.Arch != "" {
			// normal case, append and go to the next platform
			normalized = append(normalized, p)
			continue
		}

		if p.OS == "" {
			return normalized, fmt.Errorf("platforms without OS type are not supported: %v", p)
		}

		// Arch is not specified: fill in the supported archs for the OS type
		for _, dp := range defaultPlatforms {
			if p.OS == dp.OS {
				normalized = append(normalized, dp)
			}
		}
	}
	return normalized, nil
}
