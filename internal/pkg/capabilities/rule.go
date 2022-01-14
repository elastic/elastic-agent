// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package capabilities

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v2"
)

const (
	allowKey     = "allow"
	denyKey      = "deny"
	conditionKey = "__condition__"
)

type ruler interface {
	Rule() string
}

type capabilitiesList []ruler

type ruleDefinitions struct {
	Version      string           `yaml:"version" json:"version"`
	Capabilities capabilitiesList `yaml:"capabilities" json:"capabilities"`
}

func (r *capabilitiesList) UnmarshalJSON(p []byte) error {
	var tmpArray []json.RawMessage

	err := json.Unmarshal(p, &tmpArray)
	if err != nil {
		return err
	}

	for i, t := range tmpArray {
		mm := make(map[string]interface{})
		if err := json.Unmarshal(t, &mm); err != nil {
			return err
		}

		if _, found := mm["input"]; found {
			cap := &inputCapability{}
			if err := json.Unmarshal(t, &cap); err != nil {
				return err
			}
			(*r) = append((*r), cap)

		} else if _, found = mm["output"]; found {
			cap := &outputCapability{}
			if err := json.Unmarshal(t, &cap); err != nil {
				return err
			}
			(*r) = append((*r), cap)

		} else if _, found = mm["upgrade"]; found {
			cap := &upgradeCapability{}
			if err := json.Unmarshal(t, &cap); err != nil {
				return err
			}
			(*r) = append((*r), cap)
		} else {
			return fmt.Errorf("unexpected capability type for definition number '%d'", i)
		}
	}

	return nil
}

func (r *capabilitiesList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmpArray []map[string]interface{}

	err := unmarshal(&tmpArray)
	if err != nil {
		return err
	}

	for i, mm := range tmpArray {
		partialYaml, err := yaml.Marshal(mm)
		if err != nil {
			return err
		}
		if _, found := mm["input"]; found {
			cap := &inputCapability{}
			if err := yaml.Unmarshal(partialYaml, &cap); err != nil {
				return err
			}
			(*r) = append((*r), cap)

		} else if _, found = mm["output"]; found {
			cap := &outputCapability{}
			if err := yaml.Unmarshal(partialYaml, &cap); err != nil {
				return err
			}
			(*r) = append((*r), cap)

		} else if _, found = mm["upgrade"]; found {
			cap := &upgradeCapability{}
			if err := yaml.Unmarshal(partialYaml, &cap); err != nil {
				return err
			}
			(*r) = append((*r), cap)
		} else {
			return fmt.Errorf("unexpected capability type for definition number '%d'", i)
		}
	}

	return nil
}
