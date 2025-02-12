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

	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/component"
)

const (
	FlavorBasic   = "basic"
	FlavorServers = "servers"

	DefaultFlavor  = FlavorBasic
	flavorFileName = ".flavor"
)

type SkipFn func(relPath string) bool

var ErrUnknownFlavor = fmt.Errorf("unknown flavor")

type FlavorDefinition struct {
	Name       string
	Components []string
}

func UsedFlavor(topPath, defaultFlavor string) (string, error) {
	filename := filepath.Join(topPath, flavorFileName)
	content, err := os.ReadFile(filename)
	if err != nil {
		// file does not exist, flavor was not marked probably due to earlier version
		// fallback to default if defined
		if defaultFlavor != "" && os.IsNotExist(err) {
			return defaultFlavor, nil
		}

		// failed reading flavor, do not break behavior and apply none as widest
		return "", fmt.Errorf("failed reading flavor marker file: %w", err)
	}

	return string(content), nil
}

func Flavor(detectedFlavor string, registryPath string, flavorsRegistry map[string][]string) (FlavorDefinition, error) {
	if flavorsRegistry == nil {
		f, err := os.Open(registryPath)
		if err != nil {
			if os.IsNotExist(err) {
				return FlavorDefinition{}, ErrUnknownFlavor
			}

			return FlavorDefinition{}, fmt.Errorf("failed opening flavor registry: %w", err)
		}
		manifest, err := v1.ParseManifest(f)
		if err != nil {
			return FlavorDefinition{}, fmt.Errorf("failed parsing flavor registry: %w", err)
		}
		defer f.Close()
		flavorsRegistry = manifest.Package.Flavors
	}

	components, found := flavorsRegistry[detectedFlavor]
	if !found {
		return FlavorDefinition{}, ErrUnknownFlavor
	}

	return FlavorDefinition{detectedFlavor, components}, nil
}

// SpecsForFlavor returns spec files associated with specific flavor
func SpecsForFlavor(flavor FlavorDefinition) []string {
	specs := []string{}
	for _, component := range flavor.Components {
		specs = append(specs, fmt.Sprintf("%s.spec.yml", component))
	}

	return specs
}

// ApplyFlavor scans agent comonents directory and removes anything
// that is not mapped and needed for currently used flavor
func ApplyFlavor(versionedHome string, flavor FlavorDefinition) error {
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
		return fmt.Errorf("failed traversing components directory: %w", err)
	}

	for _, ftr := range filesToRemove {
		if removeErr := os.RemoveAll(ftr); !os.IsNotExist(removeErr) {
			err = fmt.Errorf("failed cleaning components: %w", removeErr)
		}
	}

	return err
}

// SkipComponentsPathWithSubpathsFn returns a skip function that returns true if
// path is not part of a any component associated with flavor.
// Paths are detected from spec files located in versionHome/components
func SkipComponentsPathFn(versionedHome string, flavor FlavorDefinition) (SkipFn, error) {
	if flavor.Name == "" {
		return func(relPath string) bool { return false }, nil
	}
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
	if runtime.GOOS == "windows" {
		relPath = strings.ReplaceAll(relPath, "\\", "/")
	}
	componentsDir := "/components/"
	componentsIdx := strings.Index(relPath, componentsDir)
	if componentsIdx == -1 {
		// not a components subpath, not blocking
		return false
	}

	subPath := relPath[componentsIdx+len(componentsDir):]

	subDirsSuffix := `/*`
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

// markFlavor persists flavor used with agent.
// This mark is used during upgrades in order to upgrade to proper set.
func markFlavor(topPath string, flavor string) error {
	filename := filepath.Join(topPath, flavorFileName)
	if err := os.WriteFile(filename, []byte(flavor), 0o600); err != nil {
		return fmt.Errorf("failed marking flavor: %w", err)
	}

	return nil
}

// allowedSubpathsForFlavor returns allowed /components/* subpath for specific flavors
// includes components, spec files, config files and other files specified in spec
func allowedSubpathsForFlavor(versionedHome string, flavor FlavorDefinition) ([]string, error) {
	var sourceComponentsDir string
	if versionedHome != "" {
		sourceComponentsDir = filepath.Join(versionedHome, "components")
	}

	allowedPaths := make([]string, 0)
	for _, component := range flavor.Components {
		subpaths, err := subpathsForComponent(component, sourceComponentsDir)
		if err != nil {
			return nil, err
		}
		allowedPaths = append(allowedPaths, subpaths...)
	}

	return allowedPaths, nil
}

func subpathsForComponent(componentName, sourceComponentsDir string) ([]string, error) {
	if componentName == "" {
		return nil, fmt.Errorf("empty component name")
	}
	specFilename := fmt.Sprintf("%s.spec.yml", componentName)
	content, err := os.ReadFile(filepath.Join(sourceComponentsDir, specFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed reading spec file for component %q: %w", componentName, err)
	}

	return component.ParseComponentFiles(content, specFilename, true)
}
