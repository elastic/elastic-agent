package component

import (
	"github.com/elastic/go-ucfg/yaml"
)

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
