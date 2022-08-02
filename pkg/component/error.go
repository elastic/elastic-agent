// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

// errorReason is an error that can be marshalled/unmarshalled to and from YAML.
type errorReason struct {
	reason string
}

func newError(reason string) error {
	return &errorReason{reason: reason}
}

func (e *errorReason) Error() string {
	return e.reason
}

func (e *errorReason) MarshalYAML() (interface{}, error) {
	return e.reason, nil
}

func (e *errorReason) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	e.reason = s
	return nil
}
