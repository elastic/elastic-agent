// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"fmt"
	"strings"
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
		{`domain\usér`, false},
	}

	for _, tc := range testCases {
		result, err := isWindowsDomainUsername(tc.username)
		assert.NoError(t, err)
		assert.Equal(t, tc.expected, result)
	}
}

func TestWithServiceOption(t *testing.T) {
	testCases := []struct {
		name                string
		groupName           string
		password            string
		expectedServiceOpts []serviceOpt
		expectedError       string
	}{
		{"", "", "", []serviceOpt{}, ""},
		{"nonDomainUsername", "", "changeme", []serviceOpt{}, "username is not in proper format 'domain\\username', contains illegal character"},
		{`domain\username`, "", "changeme", []serviceOpt{withUserGroup(`domain\username`, ""), withPassword("changeme")}, ""},
		{`domain\username`, "group", "changeme", []serviceOpt{withUserGroup(`domain\username`, "group"), withPassword("changeme")}, ""},
	}

	for i, tc := range testCases {
		t.Run(
			fmt.Sprintf("test case #%d: %s:%s:%s", i, tc.name, tc.groupName, tc.password),
			func(t *testing.T) {
				serviceOpts, err := withServiceOptions(tc.name, tc.groupName, tc.password)

				if tc.expectedError != "" {
					assert.True(t, strings.Contains(err.Error(), tc.expectedError))
				}

				assert.Equal(t, tc.expectedServiceOpts, serviceOpts)
			})
	}
}
