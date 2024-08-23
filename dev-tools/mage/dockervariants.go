// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mage

import (
	"fmt"
	"strings"
)

const (
	undefined = "undefined"
	basic     = "basic"
	ubi       = "ubi"
	wolfi     = "wolfi"
	complete  = "complete"
	cloud     = "cloud"
	service   = "service"
)

// DockerVariant defines the docker variant to build.
type DockerVariant int

// List of possible docker variants.
const (
	Undefined = iota
	Basic
	UBI
	Wolfi
	Complete
	Cloud
	Service
)

// String returns the name of the docker variant type.
func (typ DockerVariant) String() string {
	switch typ {
	case Undefined:
		return undefined
	case Basic:
		return basic
	case UBI:
		return ubi
	case Wolfi:
		return wolfi
	case Complete:
		return complete
	case Cloud:
		return cloud
	case Service:
		return service
	default:
		return invalid
	}
}

// MarshalText returns the text representation of DockerVariant.
func (typ DockerVariant) MarshalText() ([]byte, error) {
	return []byte(typ.String()), nil
}

// UnmarshalText returns a DockerVariant based on the given text.
func (typ *DockerVariant) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "":
		*typ = Undefined
	case basic:
		*typ = Basic
	case ubi:
		*typ = UBI
	case wolfi:
		*typ = Wolfi
	case complete:
		*typ = Complete
	case cloud:
		*typ = Cloud
	case service:
		*typ = Service
	default:
		return fmt.Errorf("unknown docker variant: %v", string(text))
	}
	return nil
}
