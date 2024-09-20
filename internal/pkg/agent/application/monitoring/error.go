// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import "fmt"

func errorWithStatus(status int, err error) *statusError {
	return &statusError{
		err:    err,
		status: status,
	}
}

func errorfWithStatus(status int, msg string, args ...string) *statusError {
	err := fmt.Errorf(msg, args)
	return errorWithStatus(status, err)
}

// StatusError holds correlation between error and a status
type statusError struct {
	err    error
	status int
}

func (s *statusError) Status() int {
	return s.status
}

func (s *statusError) Error() string {
	return s.err.Error()
}
