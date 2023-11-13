// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import "errors"

var (
	// ErrGroupNotFound returned when group is not found.
	ErrGroupNotFound = errors.New("group not found")
	// ErrUserNotFound returned when user is not found.
	ErrUserNotFound = errors.New("user not found")
)
