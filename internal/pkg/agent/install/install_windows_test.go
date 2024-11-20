// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsWindowsUsername(t *testing.T) {
	testCases := []struct {
		username string
		expected bool
	}{
		{``, false},
		{`user`, false},
		{`domain\user`, true},
		{`domain/user`, false},
		{`domain/domain\user`, false},
		{`domain\subdomain\user`, false},
		{`dom,ain\user`, false},
		{`doma~in\user`, false},
		{`domai:n\user`, false},
		{`dom.ain\user`, true},
		{`dom.ain\.user`, true},
	}

	for _, tc := range testCases {
		result, err := isWindowsDomainUsername(tc.username)
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, result)
	}
}
