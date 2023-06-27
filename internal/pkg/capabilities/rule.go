// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package capabilities

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

// capabilitiesList deserializes a YAML list of capabilities into organized
// arrays based on their type, for easy use by capabilitiesManager.
type capabilitiesList struct {
	inputCaps   []*inputCapability
	outputCaps  []*outputCapability
	upgradeCaps []*upgradeCapability
}

// a type for capability values that must equal "allow" or "deny", enforced
// during deserialization via its Validate function.
type allowOrDeny string

const (
	ruleTypeAllow allowOrDeny = "allow"
	ruleTypeDeny  allowOrDeny = "deny"
)

// The in-memory struct representing capabilities.yml. Used for deserializing
// when loading capabilitiessManager.
type capabilitiesSpec struct {
	Capabilities capabilitiesList `yaml:"capabilities"`
}

func (r *capabilitiesList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var capabilityConfigs []map[string]interface{}

	err := unmarshal(&capabilityConfigs)
	if err != nil {
		return err
	}

	for i, mm := range capabilityConfigs {
		partialYaml, err := yaml.Marshal(mm)
		if err != nil {
			return err
		}
		if _, found := mm["input"]; found {
			cap := &inputCapability{}
			if err := yaml.Unmarshal(partialYaml, &cap); err != nil {
				return err
			}
			r.inputCaps = append(r.inputCaps, cap)

		} else if _, found = mm["output"]; found {
			cap := &outputCapability{}
			if err := yaml.Unmarshal(partialYaml, &cap); err != nil {
				return err
			}
			r.outputCaps = append(r.outputCaps, cap)

		} else if _, found = mm["upgrade"]; found {
			// Serialize upgrade constraints to a temporary struct so we can
			// safely assemble the associated EQL expression
			spec := struct {
				Type      allowOrDeny `yaml:"rule"`
				Condition string      `yaml:"upgrade"`
			}{}
			if err := yaml.Unmarshal(partialYaml, &spec); err != nil {
				return err
			}
			cap, err := newUpgradeCapability(spec.Condition, spec.Type)
			if err != nil {
				return err
			}
			r.upgradeCaps = append(r.upgradeCaps, cap)
		} else {
			return fmt.Errorf("unexpected capability type for definition number '%d'", i)
		}
	}

	return nil
}

func (ad allowOrDeny) Validate() error {
	if ad != ruleTypeAllow && ad != ruleTypeDeny {
		return fmt.Errorf("capability rule was %q, expected 'allow' or 'deny'", ad)
	}
	return nil
}
