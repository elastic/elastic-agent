// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"gopkg.in/yaml.v3"
)

const (
	FlavorBasic   = "basic"
	FlavorServers = "servers"

	DefaultFlavor  = FlavorBasic
	flavorFileName = ".flavor"
)

type SkipFn func(relPath string) bool

var ErrUnknownFlavor = fmt.Errorf("unknown flavor")

var flavorsRegistry map[string][]string = map[string][]string{
	FlavorBasic: {
		"agentbeat",
		"osqueryd",
		"endpoint-security",
		"pf-host-agent",
	},
	FlavorServers: {
		"agentbeat",
		"osqueryd",
		"endpoint-security",
		"pf-host-agent",
		"cloudbeat",
		"apm-server",
		"fleet-server",
		"pf-elastic-symbolizer",
		"pf-elastic-collector",
	},
}

// SpecsForFlavor returns spec files associated with specific flavor
func SpecsForFlavor(flavor string) ([]string, error) {
	components, err := componentsForFlavor(flavor, false)
	if err != nil {
		return nil, err
	}

	specs := []string{}
	for _, component := range components {
		specs = append(specs, fmt.Sprintf("%s.spec.yml", component))
	}

	return specs, nil
}

// MarkFlavor persists flavor used with agent.
// This mark is used during upgrades in order to upgrade to proper set.
func MarkFlavor(topPath string, flavor string) error {
	filename := filepath.Join(topPath, flavorFileName)
	if err := os.WriteFile(filename, []byte(flavor), 0o600); err != nil {
		return fmt.Errorf("failed marking flavor: %w", err)
	}

	return nil
}

// Flavor reads flavor from mark file.
// In case file exists and contains invalid flavor ErrUnknownFlavor is returned
func Flavor(topPath string, defaultFlavor string, log *logger.Logger) (string, error) {
	filename := filepath.Join(topPath, flavorFileName)
	content, err := os.ReadFile(filename)
	if err != nil {
		// file does not exist, flavor was not marked probably due to earlier version
		// fallback to default if defined
		if defaultFlavor != "" && os.IsNotExist(err) {
			return defaultFlavor, nil
		}

		// failed reading flavor, do not break behavior and apply none as widest
		log.Warnf("failed detecting flavor: %v", err)
		return "", nil
	}

	detectedFlavor := string(content)
	_, found := flavorsRegistry[detectedFlavor]
	if !found {
		log.Warnf("unknown flavor detected: %v", detectedFlavor)
		return "", ErrUnknownFlavor
	}

	return detectedFlavor, nil
}

// ApplyFlavor scans agent comonents directory and removes anything
// that is not mapped and needed for currently used flavor
func ApplyFlavor(versionedHome string, flavor string) error {
	skipFn, err := SkipComponentsPathFn(versionedHome, flavor)
	if err != nil {
		return err
	}

	componentsDir := filepath.Join(versionedHome, "components")
	filesToRemove := []string{}

	err = filepath.Walk(componentsDir, func(path string, info fs.FileInfo, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("walk on %q failed: %w", componentsDir, err)
		}

		if skipFn != nil && skipFn(path) {
			// remove as file is not needed
			filesToRemove = append(filesToRemove, path)
		}

		return nil
	})
	if err != nil {
		return err
	}

	for _, ftr := range filesToRemove {
		if removeErr := os.RemoveAll(ftr); !os.IsNotExist(removeErr) {
			err = removeErr
		}
	}

	return err
}

// ParseComponentFiles parses spec files and returns list of associated paths with component.
// Default set consisting of binary, spec file and default config file is always present
func ParseComponentFiles(content []byte, filename string, includeDefaults bool) ([]string, error) {
	def := struct {
		Files []string `yaml:"component_files"`
	}{}

	if err := yaml.Unmarshal(content, &def); err != nil {
		return nil, err
	}

	var files []string
	files = append(files, def.Files...)

	if includeDefaults {
		component := strings.TrimSuffix(filepath.Base(filename), ".spec.yml")
		binaryName := component
		if runtime.GOOS == "windows" {
			binaryName += ".exe"
		}
		files = append(files,
			binaryName,
			fmt.Sprintf("%s.spec.yml", component),
			fmt.Sprintf("%s.yml", component))
	}

	return files, nil
}

// SkipComponentsPathWithSubpathsFn returns a skip function that returns true if
// path is not part of a any component associated with flavor.
// Paths are detected from spec files located in versionHome/components
func SkipComponentsPathFn(versionedHome, flavor string) (SkipFn, error) {
	allowedSubpaths, err := allowedSubpathsForFlavor(versionedHome, flavor)
	if err != nil {
		return nil, err
	}

	return SkipComponentsPathWithSubpathsFn(allowedSubpaths)
}

// SkipComponentsPathWithSubpathsFn with already known set of allowed subpaths.
// allow list is not detected from spec files in this case
func SkipComponentsPathWithSubpathsFn(allowedSubpaths []string) (SkipFn, error) {
	return func(relPath string) bool {
		return skipComponentsPath(relPath, allowedSubpaths)
	}, nil
}

func skipComponentsPath(relPath string, allowedSubpaths []string) bool {
	if allowedSubpaths == nil {
		return false
	}

	componentsDir := fmt.Sprintf("%ccomponents%c", os.PathSeparator, os.PathSeparator)
	componentsIdx := strings.Index(relPath, componentsDir)
	if componentsIdx == -1 {
		// not a components subpath, not blocking
		return false
	}

	subPath := relPath[componentsIdx+len(componentsDir):]
	subDirsSuffix := fmt.Sprintf("%c*", os.PathSeparator)
	for _, allowedSubpath := range allowedSubpaths {
		if allowedSubpath == subPath {
			// exact match is allowed
			return false
		}
		if strings.HasSuffix(allowedSubpath, subDirsSuffix) {
			trimmed := strings.TrimSuffix(allowedSubpath, "*")
			dirName := strings.TrimSuffix(allowedSubpath, subDirsSuffix)
			// it is either same dir (create dir) or has dir prefix (copy content)
			// do not evaluate true for subPath=abcd/ef and trimmed=ab
			if subPath == dirName || strings.HasPrefix(subPath, trimmed) {
				return false
			}
		}
	}

	return true
}

// allowedSubpathsForFlavor returns allowed /components/* subpath for specific flavors
// includes components, spec files, config files and other files specified in spec
func allowedSubpathsForFlavor(versionedHome, flavor string) ([]string, error) {
	components, err := componentsForFlavor(flavor, true)
	if err != nil {
		return nil, err
	}

	var sourceComponentsDir string
	if versionedHome != "" {
		sourceComponentsDir = filepath.Join(versionedHome, "components")
	}

	allowedPaths := make([]string, 0)
	for _, component := range components {
		subpaths, err := subpathsForComponent(component, sourceComponentsDir)
		if err != nil {
			return nil, err
		}
		allowedPaths = append(allowedPaths, subpaths...)
	}

	fmt.Println("compiled allowed paths", allowedPaths)
	return allowedPaths, nil
}

func subpathsForComponent(component, sourceComponentsDir string) ([]string, error) {
	specFilename := fmt.Sprintf("%s.spec.yml", component)
	content, err := os.ReadFile(filepath.Join(sourceComponentsDir, specFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	return ParseComponentFiles(content, specFilename, true)
}

// componentsForFlavor returns a list of components for selected flavor.
// In case no flavor is provided components for 'basic' are returned.
// ErrUnknownFlavor is returned in case flavor is not recognized.
func componentsForFlavor(flavor string, allowFallback bool) ([]string, error) {
	if flavor == "" && allowFallback {
		flavor = DefaultFlavor
	}
	components, found := flavorsRegistry[flavor]
	if !found {
		return nil, ErrUnknownFlavor
	}

	return components, nil
}
