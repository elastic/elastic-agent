// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package capabilities

import (
	"errors"
	"io"
	"io/fs"
	"os"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type Capabilities interface {
	AllowUpgrade(version string, sources []string) bool
	FilterUpgradeSources(version string, sources []string) []string
	AllowInput(name string) bool
	AllowOutput(name string) bool
	AllowFleetOverride() bool
}

type capabilitiesManager struct {
	log               *logger.Logger
	inputChecks       []*stringMatcher
	outputChecks      []*stringMatcher
	upgradeCaps       []*upgradeCapability
	fleetOverrideCaps []*fleetOverrideCapability
}

func (cm *capabilitiesManager) AllowInput(inputType string) bool {
	return matchString(inputType, cm.inputChecks)
}

func (cm *capabilitiesManager) AllowOutput(outputType string) bool {
	return matchString(outputType, cm.outputChecks)
}

func (cm *capabilitiesManager) AllowUpgrade(version string, sources []string) bool {
	if len(sources) == 0 {
		return allowUpgrade(cm.log, version, "", cm.upgradeCaps)
	}
	for _, source := range sources {
		if allowUpgrade(cm.log, version, source, cm.upgradeCaps) {
			return true
		}
	}
	return false
}

func (cm *capabilitiesManager) FilterUpgradeSources(version string, sources []string) []string {
	allowed := make([]string, 0, len(sources))
	for _, source := range sources {
		if allowUpgrade(cm.log, version, source, cm.upgradeCaps) {
			allowed = append(allowed, source)
		} else {
			cm.log.Infof("Upgrade source %q filtered by capabilities.yml", source)
		}
	}
	return allowed
}

func (cm *capabilitiesManager) AllowFleetOverride() bool {
	return allowFleetOverride(cm.log, cm.fleetOverrideCaps)
}

func LoadFile(capsFile string, log *logger.Logger) (Capabilities, error) {
	// load capabilities from file
	fd, err := os.Open(capsFile)
	if errors.Is(err, fs.ErrNotExist) {
		// No file, return an empty capabilities manager
		log.Infof("Capabilities file not found in %s", capsFile)
		return &capabilitiesManager{}, nil
	}
	if err != nil {
		return nil, err
	}

	// We successfully opened the file, pass it through to Load
	defer fd.Close()
	return Load(fd, log)
}

// Load loads capabilities data and prepares manager.
func Load(capsReader io.Reader, log *logger.Logger) (Capabilities, error) {

	spec := &capabilitiesSpec{}
	dec := yaml.NewDecoder(capsReader)
	if err := dec.Decode(&spec); err != nil {
		return &capabilitiesManager{}, err
	}
	caps := spec.Capabilities

	return &capabilitiesManager{
		log:               log,
		inputChecks:       caps.inputChecks,
		outputChecks:      caps.outputChecks,
		upgradeCaps:       caps.upgradeChecks,
		fleetOverrideCaps: caps.fleetOverrideChecks,
	}, nil
}
