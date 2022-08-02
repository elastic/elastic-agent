// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/elastic/go-ucfg/yaml"
)

const (
	specSuffix      = ".spec.yml"
	specGlobPattern = "*" + specSuffix
)

var (
	// ErrInputNotSupported is returned when the input is not supported on any platform
	ErrInputNotSupported = newError("input not supported")
	// ErrInputNotSupportedOnPlatform is returned when the input is supported but not on this platform
	ErrInputNotSupportedOnPlatform = newError("input not supported on this platform")
)

// InputRuntimeSpec returns the specification for running this input on the current platform.
type InputRuntimeSpec struct {
	InputType  string    `yaml:"input_type"`
	BinaryName string    `yaml:"binary_name"`
	BinaryPath string    `yaml:"binary_path"`
	Spec       InputSpec `yaml:"spec"`
}

// RuntimeSpecs return all the specifications for inputs that are supported on the current platform.
type RuntimeSpecs struct {
	// platform that was loaded
	platform PlatformDetail

	// inputTypes all input types even if that input is not supported on the current platform
	inputTypes []string

	// inputSpecs only the input specs for the current platform
	inputSpecs map[string]InputRuntimeSpec

	// aliasMapping maps aliases to real input name
	aliasMapping map[string]string
}

type loadRuntimeOpts struct {
	skipBinaryCheck bool
}

// LoadRuntimeOption are options for loading the runtime specs.
type LoadRuntimeOption func(o *loadRuntimeOpts)

// SkipBinaryCheck skips checking that a binary is next to the runtime.
func SkipBinaryCheck() LoadRuntimeOption {
	return func(o *loadRuntimeOpts) {
		o.skipBinaryCheck = true
	}
}

// LoadRuntimeSpecs loads all the component input specifications from the provided directory.
//
// Returns a mapping of the input to binary name with specification for that input. The filenames in the directory
// are required to be {binary-name} with {binary-name}.spec.yml to be next to it. If a {binary-name}.spec.yml exists
// but no matching {binary-name} is found that will result in an error. If a {binary-name} exists without a
// {binary-name}.spec.yml then it will be ignored.
func LoadRuntimeSpecs(dir string, platform PlatformDetail, opts ...LoadRuntimeOption) (RuntimeSpecs, error) {
	var opt loadRuntimeOpts
	for _, o := range opts {
		o(&opt)
	}
	matches, err := filepath.Glob(filepath.Join(dir, specGlobPattern))
	if err != nil {
		return RuntimeSpecs{}, err
	}
	var types []string
	mapping := make(map[string]InputRuntimeSpec)
	aliases := make(map[string]string)
	for _, match := range matches {
		binaryName := filepath.Base(match[:len(match)-len(specGlobPattern)+1])
		binaryPath := match[:len(match)-len(specGlobPattern)+1]
		if platform.OS == Windows {
			binaryPath += ".exe"
		}
		if !opt.skipBinaryCheck {
			info, err := os.Stat(binaryPath)
			if errors.Is(err, os.ErrNotExist) {
				return RuntimeSpecs{}, fmt.Errorf("missing matching binary for %s", match)
			} else if err != nil {
				return RuntimeSpecs{}, fmt.Errorf("failed to stat %s: %w", binaryPath, err)
			} else if info.IsDir() {
				return RuntimeSpecs{}, fmt.Errorf("missing matching binary for %s", match)
			}
		}
		data, err := ioutil.ReadFile(match)
		if err != nil {
			return RuntimeSpecs{}, fmt.Errorf("failed reading spec %s: %w", match, err)
		}
		spec, err := LoadSpec(data)
		if err != nil {
			return RuntimeSpecs{}, fmt.Errorf("failed reading spec %s: %w", match, err)
		}
		for _, input := range spec.Inputs {
			if !containsStr(types, input.Name) {
				types = append(types, input.Name)
			}
			if !containsStr(input.Platforms, platform.String()) {
				// input spec doesn't support this platform
				continue
			}
			if existing, exists := mapping[input.Name]; exists {
				return RuntimeSpecs{}, fmt.Errorf("failed loading spec '%s': input '%s' already exists in spec '%s'", match, input.Name, existing.BinaryName)
			}
			if existing, exists := aliases[input.Name]; exists {
				return RuntimeSpecs{}, fmt.Errorf("failed loading spec '%s': input '%s' collides with an alias from another input '%s'", match, input.Name, existing)
			}
			for _, alias := range input.Aliases {
				if existing, exists := mapping[alias]; exists {
					return RuntimeSpecs{}, fmt.Errorf("failed loading spec '%s': input alias '%s' collides with an already defined input in spec '%s'", match, alias, existing.BinaryName)
				}
				if existing, exists := aliases[alias]; exists {
					return RuntimeSpecs{}, fmt.Errorf("failed loading spec '%s': input alias '%s' collides with an already defined input alias for input '%s'", match, alias, existing)
				}
			}
			mapping[input.Name] = InputRuntimeSpec{
				InputType:  input.Name,
				BinaryName: binaryName,
				BinaryPath: binaryPath,
				Spec:       input,
			}
			for _, alias := range input.Aliases {
				aliases[alias] = input.Name
			}
		}
	}
	return RuntimeSpecs{
		platform:     platform,
		inputTypes:   types,
		inputSpecs:   mapping,
		aliasMapping: aliases,
	}, nil
}

// Inputs returns the list of supported inputs for this platform.
func (r *RuntimeSpecs) Inputs() []string {
	inputs := make([]string, 0, len(r.inputSpecs))
	for inputType := range r.inputSpecs {
		inputs = append(inputs, inputType)
	}
	return inputs
}

// GetInput returns the input runtime specification for this input on this platform.
func (r *RuntimeSpecs) GetInput(inputType string) (InputRuntimeSpec, error) {
	runtime, ok := r.inputSpecs[inputType]
	if ok {
		return runtime, nil
	}
	if containsStr(r.inputTypes, inputType) {
		// supported but not on this platform
		return InputRuntimeSpec{}, ErrInputNotSupportedOnPlatform
	}
	// not supported at all
	return InputRuntimeSpec{}, ErrInputNotSupported
}

// LoadSpec loads the component specification.
//
// Will error in the case that the specification is not valid. Only valid specifications are allowed.
func LoadSpec(data []byte) (Spec, error) {
	var spec Spec
	cfg, err := yaml.NewConfig(data)
	if err != nil {
		return spec, err
	}
	err = cfg.Unpack(&spec)
	if err != nil {
		return spec, err
	}
	return spec, nil
}

func containsStr(s []string, v string) bool {
	for _, i := range s {
		if i == v {
			return true
		}
	}
	return false
}
