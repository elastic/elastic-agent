// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetEnvMap(t *testing.T) {
	singleValMapKey := "single_val_key"
	multiValMapKey := "multi_val_key"
	testCases := []struct {
		name     string
		env      map[string]string
		expected map[string]string
	}{
		{
			name: "basic",
			env: map[string]string{
				singleValMapKey: "key1=value1",
				multiValMapKey:  "key2=value2,key3=value3",
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
			},
		},
		{
			name: "override",
			env: map[string]string{
				singleValMapKey: "key1=value1",
				multiValMapKey:  "key1=value2,key3=value3",
			},
			expected: map[string]string{
				"key1": "value2",
				"key3": "value3",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			singleValKey := t.Name() + "_SINGLE"
			multiValKey := t.Name() + "_MULTI"

			t.Setenv(singleValKey, tc.env[singleValMapKey])
			t.Setenv(multiValKey, tc.env[multiValMapKey])
			defer os.Unsetenv(singleValKey)
			defer os.Unsetenv(multiValKey)

			res := getEnvMap(singleValKey, multiValKey)
			require.EqualValues(t, tc.expected, res)
		})
	}
}
