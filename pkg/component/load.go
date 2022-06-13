// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	ucfg "github.com/elastic/go-ucfg/yaml"
	"gopkg.in/yaml.v2"
)

var SpecSuffix = ".spec.yml" // TODO: change after beat ignores yml config

// LoadSpec loads the component specification.
//
// Will error in the case that the specification is not valid. Only valid specifications are allowed.
func LoadSpec(data []byte) (Spec, error) {
	var spec Spec
	cfg, err := ucfg.NewConfig(data)
	if err != nil {
		return spec, err
	}
	err = cfg.Unpack(&spec)
	if err != nil {
		return spec, err
	}
	return spec, nil
}

// ReadSpecs reads all the specs that match the provided globbing path.
func ReadSpecs(path string) ([]Spec, error) {
	var specs []Spec
	files, err := filepath.Glob(filepath.Join(path, "*"+SpecSuffix))
	if err != nil {
		return []Spec{}, errors.New(err, "could not include spec", errors.TypeConfig)
	}

	for _, f := range files {
		data, err := ioutil.ReadFile(f)
		if err != nil {
			return []Spec{}, errors.New(err, fmt.Sprintf("could not read spec %s", f), errors.TypeConfig)
		}

		name := strings.TrimSuffix(filepath.Base(f), SpecSuffix)
		spec := Spec{Name: name}
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return []Spec{}, errors.New(err, "could not unmarshal YAML", errors.TypeConfig)
		}
		specs = append(specs, spec)
	}

	return specs, nil
}

// FindSpecByName find a spec by name and return it or false if we cannot find it.
// TODO: remove
func FindSpecByName(name string) (Spec, bool) {
	for _, dt := range Supported {
		for _, candidate := range dt {
			if strings.EqualFold(name, candidate.Name) {
				return candidate.Spec, true
			}
		}
	}
	return Spec{}, false
}
