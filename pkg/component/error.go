// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

// ErrorReason is an error that can be marshalled/unmarshalled to and from YAML.
type ErrorReason struct {
	Reason string
}

func newError(reason string) error {
	return &ErrorReason{Reason: reason}
}

func (e *ErrorReason) Error() string {
	return e.Reason
}

func (e *ErrorReason) MarshalYAML() (interface{}, error) {
	return e.Reason, nil
}

func (e *ErrorReason) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	e.Reason = s
	return nil
}
