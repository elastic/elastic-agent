// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const PackageVersionFilename = ".package-version"

type packageVersion struct {
	Version      string `json:"version"`
	BuildID      string `json:"build_id"`
	ManifestURL  string `json:"manifest_url"`
	SummaryURL   string `json:"summary_url"`
	CoreVersion  string `json:"core_version"`
	StackVersion string `json:"stack_version"`
	StackBuildID string `json:"stack_build_id"`
}

func initPackageVersion() error {
	if os.Getenv("USE_PACKAGE_VERSION") != "true" {
		return nil
	}

	_, err := os.Stat(PackageVersionFilename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("USE_PACKAGE_VERSION is set, but %q does not exist, not overriding\n", PackageVersionFilename)
			return nil
		}
		return fmt.Errorf("failed to stat %q: %w", PackageVersionFilename, err)
	}

	pv, err := readPackageVersion()
	if err != nil {
		// err is wrapped in readPackageVersion
		return err
	}

	PackagingFromManifest = true
	ManifestURL = pv.ManifestURL
	agentPackageVersion = pv.CoreVersion
	Snapshot = true

	_ = os.Setenv("BEAT_VERSION", pv.CoreVersion)
	_ = os.Setenv("AGENT_VERSION", pv.Version)
	_ = os.Setenv("AGENT_STACK_VERSION", pv.StackVersion)
	_ = os.Setenv("SNAPSHOT", "true")

	dropPath := filepath.Join("build", "distributions", "elastic-agent-drop")
	dropPath, err = filepath.Abs(dropPath)
	if err != nil {
		return fmt.Errorf("failed to obtain absolute path for default drop path: %w", err)
	}

	_ = os.Setenv("AGENT_DROP_PATH", dropPath)

	return nil
}

func UpdatePackageVersion(version, buildID, stackVersion, stackBuildId, manifestURL, summaryURL string) error {
	packageVersion := packageVersion{
		Version:      version,
		BuildID:      buildID,
		ManifestURL:  manifestURL,
		SummaryURL:   summaryURL,
		CoreVersion:  strings.ReplaceAll(version, "-SNAPSHOT", ""),
		StackVersion: stackVersion,
		StackBuildID: stackBuildId,
	}

	if err := writePackageVersion(packageVersion); err != nil {
		// err is wrapped in writePackageVersion
		return err
	}
	return nil
}

func writePackageVersion(pv packageVersion) error {
	pvBytes, err := json.MarshalIndent(pv, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal package version: %w", err)
	}

	err = os.WriteFile(PackageVersionFilename, pvBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write package version: %w", err)
	}

	return nil
}

func readPackageVersion() (*packageVersion, error) {
	f, err := os.Open(PackageVersionFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to open %q for read: %w", PackageVersionFilename, err)
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	pVersion := &packageVersion{}
	err = decoder.Decode(pVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to decode YAML from file %q: %w", PackageVersionFilename, err)
	}
	return pVersion, nil
}
