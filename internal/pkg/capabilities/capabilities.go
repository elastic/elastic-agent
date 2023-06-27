// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package capabilities

import (
	"errors"
	"io/fs"
	"os"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Capability provides a way of applying predefined filter to object.
// It's up to capability to determine if capability is applicable on object.
type Capability interface {
	// Apply applies capabilities on input and returns true if input should be completely blocked
	// otherwise, false and updated input is returned
	Apply(interface{}) (interface{}, error)
}

type Capabilities interface {
	AllowUpgrade(version string, sourceURI string) bool
	AllowInput(name string) bool
	AllowOutput(name string) bool
}

var (
	// ErrBlocked is returned when capability is blocking.
	ErrBlocked = errors.New("capability blocked")
)

type capabilitiesManager struct {
	allowInputType  func(string) bool
	allowOutputType func(string) bool
	allowUpgrade    func(version string, uri string) bool
	//caps []Capability
}

func (cm *capabilitiesManager) AllowInput(inputType string) bool {
	if cm.allowInputType != nil {
		return cm.allowInputType(inputType)
	}
	return true
}

func (cm *capabilitiesManager) AllowOutput(outputType string) bool {
	if cm.allowOutputType != nil {
		return cm.allowOutputType(outputType)
	}
	return true
}

func (cm *capabilitiesManager) AllowUpgrade(version string, uri string) bool {
	if cm.allowUpgrade != nil {
		return cm.allowUpgrade(version, uri)
	}
	return true
}

type capabilityFactory func(*logger.Logger, *ruleDefinitions) (Capability, error)

// Load loads capabilities files and prepares manager.
func Load(capsFile string, log *logger.Logger) (Capabilities, error) {
	cm := &capabilitiesManager{}

	// load capabilities from file
	fd, err := os.Open(capsFile)
	if errors.Is(err, fs.ErrNotExist) {
		log.Infof("Capabilities file not found in %s", capsFile)
		return cm, nil
	}
	if err != nil {
		return cm, err
	}
	defer fd.Close()

	definitions := &ruleDefinitions{}
	dec := yaml.NewDecoder(fd)
	if err := dec.Decode(&definitions); err != nil {
		return cm, err
	}

	inputCaps := newInputsCapability(definitions.Capabilities.inputCaps)
	cm.allowInputType = inputCaps.allowInput

	outputCaps := newOutputsCapability(definitions.Capabilities.outputCaps)
	cm.allowOutputType = outputCaps.allowOutput

	upgradeCaps := newUpgradesCapability(definitions.Capabilities.upgradeCaps)
	if err != nil {
		return nil, err
	}
	cm.allowUpgrade = upgradeCaps.allowUpgrade

	return cm, nil
}
