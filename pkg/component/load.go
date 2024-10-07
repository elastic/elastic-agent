// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"errors"
	"fmt"
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
	// ErrOutputNotSupported is returned when the output is not supported on any platform
	ErrOutputNotSupported = newError("output not supported")
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
	specFiles, err := specFilesForDirectory(dir)
	if err != nil {
		return RuntimeSpecs{}, err
	}
	var inputTypes []string
	inputSpecs := make(map[string]InputRuntimeSpec)
	inputAliases := make(map[string]string)
	for path, spec := range specFiles {
		binaryName := filepath.Base(path[:len(path)-len(specGlobPattern)+1])
		binaryPath := path[:len(path)-len(specGlobPattern)+1]
		if platform.OS == Windows {
			binaryPath += ".exe"
		}
		if !opt.skipBinaryCheck {
			info, err := os.Stat(binaryPath)
			if errors.Is(err, os.ErrNotExist) {
				return RuntimeSpecs{}, fmt.Errorf("missing matching binary for %s", path)
			} else if err != nil {
				return RuntimeSpecs{}, fmt.Errorf("failed to stat %s: %w", binaryPath, err)
			} else if info.IsDir() {
				return RuntimeSpecs{}, fmt.Errorf("missing matching binary for %s", path)
			}
		}
		for _, input := range spec.Inputs {
			if !containsStr(inputTypes, input.Name) {
				inputTypes = append(inputTypes, input.Name)
			}
			if !containsStr(input.Platforms, platform.String()) {
				// input spec doesn't support this platform
				continue
			}
			if existing, exists := inputSpecs[input.Name]; exists {
				return RuntimeSpecs{}, fmt.Errorf("failed loading spec '%s': input '%s' already exists in spec '%s'", path, input.Name, existing.BinaryName)
			}
			if existing, exists := inputAliases[input.Name]; exists {
				return RuntimeSpecs{}, fmt.Errorf("failed loading spec '%s': input '%s' collides with an alias from another input '%s'", path, input.Name, existing)
			}
			for _, alias := range input.Aliases {
				if existing, exists := inputSpecs[alias]; exists {
					return RuntimeSpecs{}, fmt.Errorf("failed loading spec '%s': input alias '%s' collides with an already defined input in spec '%s'", path, alias, existing.BinaryName)
				}
				if existing, exists := inputAliases[alias]; exists {
					return RuntimeSpecs{}, fmt.Errorf("failed loading spec '%s': input alias '%s' collides with an already defined input alias for input '%s'", path, alias, existing)
				}
			}
			inputSpecs[input.Name] = InputRuntimeSpec{
				InputType:  input.Name,
				BinaryName: binaryName,
				BinaryPath: binaryPath,
				Spec:       input,
			}
			for _, alias := range input.Aliases {
				inputAliases[alias] = input.Name
			}
		}
	}
	return RuntimeSpecs{
		platform:     platform,
		inputTypes:   inputTypes,
		inputSpecs:   inputSpecs,
		aliasMapping: inputAliases,
	}, nil
}

// specFilesForDirectory loads all spec files in the target directory
// into Spec structs and returns them in a map keyed by file path.
func specFilesForDirectory(dir string) (map[string]Spec, error) {
	specFiles := make(map[string]Spec)
	matches, err := filepath.Glob(filepath.Join(dir, specGlobPattern))
	if err != nil {
		return nil, err
	}
	for _, match := range matches {
		data, err := os.ReadFile(match)
		if err != nil {
			return nil, fmt.Errorf("failed reading spec %s: %w", match, err)
		}
		spec, err := LoadSpec(data)
		if err != nil {
			return nil, fmt.Errorf("failed reading spec %s: %w", match, err)
		}
		specFiles[match] = spec
	}
	return specFiles, nil
}

// NewRuntimeSpecs creates a RuntimeSpecs from already loaded input runtime specifications.
// Only used for testing.
func NewRuntimeSpecs(platform PlatformDetail, inputSpecs []InputRuntimeSpec) (RuntimeSpecs, error) {
	var inputTypes []string
	inputSpecsMap := make(map[string]InputRuntimeSpec)
	inputAliases := make(map[string]string)
	for _, inputSpec := range inputSpecs {
		if !containsStr(inputTypes, inputSpec.Spec.Name) {
			inputTypes = append(inputTypes, inputSpec.Spec.Name)
		}
		if !containsStr(inputSpec.Spec.Platforms, platform.String()) {
			// input spec doesn't support this platform
			continue
		}
		if existing, exists := inputSpecsMap[inputSpec.Spec.Name]; exists {
			return RuntimeSpecs{}, fmt.Errorf("input '%s' already exists in spec '%s'", inputSpec.Spec.Name, existing.BinaryName)
		}
		if existing, exists := inputAliases[inputSpec.Spec.Name]; exists {
			return RuntimeSpecs{}, fmt.Errorf("input '%s' collides with an alias from another input '%s'", inputSpec.Spec.Name, existing)
		}
		for _, alias := range inputSpec.Spec.Aliases {
			if existing, exists := inputAliases[alias]; exists {
				return RuntimeSpecs{}, fmt.Errorf("input alias '%s' collides with an already defined input alias for input '%s'", alias, existing)
			}
		}
		inputSpecsMap[inputSpec.Spec.Name] = inputSpec
		for _, alias := range inputSpec.Spec.Aliases {
			inputAliases[alias] = inputSpec.Spec.Name
		}
	}
	return RuntimeSpecs{
		platform:     platform,
		inputTypes:   inputTypes,
		inputSpecs:   inputSpecsMap,
		aliasMapping: inputAliases,
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

// GetInput returns the input runtime specification for the given input type on this platform.
func (r *RuntimeSpecs) GetInput(inputType string) (InputRuntimeSpec, error) {
	if !containsStr(r.inputTypes, inputType) {
		return InputRuntimeSpec{}, ErrInputNotSupported
	}
	runtimeSpec, ok := r.inputSpecs[inputType]
	if !ok {
		// supported but not on this platform
		return InputRuntimeSpec{}, ErrInputNotSupportedOnPlatform
	}
	err := validateRuntimeChecks(&runtimeSpec.Spec.Runtime, r.platform)
	// runtimeSpec is always returned so the caller know which runtime would have been used
	// even if the runtime checks return an error
	return runtimeSpec, err
}

// ServiceSpecs returns only the input specification that are based on the service runtime.
func (r *RuntimeSpecs) ServiceSpecs() []InputRuntimeSpec {
	var services []InputRuntimeSpec
	for _, s := range r.inputSpecs {
		if s.Spec.Service != nil {
			services = append(services, s)
		}
	}
	return services
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
