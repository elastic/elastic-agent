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
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	FlavorBasic   = "basic"
	FlavorServers = "servers"

	DefaultFlavor  = FlavorBasic
	flavorFileName = ".flavor"
)

var ErrUnknownFlavor = fmt.Errorf("unknown flavor")

var flavors map[string][]string = map[string][]string{
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
// Returns defaultFlavor in case file does not exists.
// In case file exists and contains invalid flavor ErrUnknownFlavor is returned
func Flavor(topPath string, defaultFlavor string) (string, error) {
	filename := filepath.Join(topPath, flavorFileName)
	content, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// file does not exist, flavor was not marked probably due to earlier version
			// fallback to default if defined
			if defaultFlavor != "" {
				return defaultFlavor, nil
			}
		}

		return "", nil
	}

	_, found := flavors[string(content)]
	if !found {
		return "", ErrUnknownFlavor
	}

	return string(content), nil
}

func ApplyFlavor(versionedHome string, flavor string) error {
	skipFn, err := SkipComponentsPathFn(flavor, versionedHome)
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

		if skipFn(path) {
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

func SkipComponentsPathFn(flavor string, versionedHome string) (func(relPath string) bool, error) {
	allowedSubpaths, err := allowedSubpathsForFlavor(flavor, versionedHome)
	if err != nil {
		return nil, err
	}

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
func allowedSubpathsForFlavor(flavor string, versionedHome string) ([]string, error) {
	components, err := componentsForFlavor(flavor)
	fmt.Println("got components for flavor", flavor, components)
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
	// TODO: read spec file
	// TODO: replace / with os.PathSeparator

	specFilename := fmt.Sprintf("%s.spec.yml", component)
	additionalFiles, err := loadPathsFromSpec(sourceComponentsDir, specFilename)
	if err != nil {
		return nil, err
	}

	return append(additionalFiles,
		component,
		specFilename,
		fmt.Sprintf("%s.yml", component)), nil
}

func loadPathsFromSpec(sourceComponentsDir, specFilename string) ([]string, error) {
	if sourceComponentsDir == "" {
		return nil, nil
	}

	def := struct {
		Files []string `yaml:"component_files"`
	}{}

	content, err := os.ReadFile(filepath.Join(sourceComponentsDir, specFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(content, &def); err != nil {
		return nil, err
	}

	return def.Files, nil
}

// componentsForFlavor returns a list of components for selected flavor.
// In case no flavor is provided components for 'basic' are returned.
// ErrUnknownFlavor is returned in case flavor is not recognized.
func componentsForFlavor(flavor string) ([]string, error) {
	if flavor == "" {
		flavor = DefaultFlavor
	}
	components, found := flavors[flavor]
	if !found {
		return nil, ErrUnknownFlavor
	}

	return components, nil
}
