// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package capabilities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringMatcher(t *testing.T) {
	testCases := []struct {
		name     string
		matchers []*stringMatcher
		allowed  []string
		blocked  []string
	}{
		{
			name: "1/1 match",
			matchers: []*stringMatcher{
				{pattern: "system/metrics", rule: "allow"},
			},
			allowed: []string{"system/metrics"},
		},
		{
			name: "0/1 match",
			matchers: []*stringMatcher{
				{pattern: "system/metrics", rule: "allow"},
			},
			allowed: []string{"system/logs"},
		},
		{
			name: "valid action - deny metrics",
			matchers: []*stringMatcher{
				{pattern: "system/metrics", rule: "deny"},
			},
			allowed: []string{"system/logs"},
			blocked: []string{"system/metrics"},
		},
		{
			name: "no match",
			matchers: []*stringMatcher{
				{pattern: "something_else", rule: "allow"},
			},
			allowed: []string{"system/metrics", "system/logs"},
		},
		{
			name: "filters metrics",
			matchers: []*stringMatcher{
				{pattern: "system/metrics", rule: "deny"},
			},
			allowed: []string{"system/logs"},
			blocked: []string{"system/metrics"},
		},
		{
			name: "allows metrics only",
			matchers: []*stringMatcher{
				{pattern: "system/metrics", rule: "allow"},
				{pattern: "*", rule: "deny"},
			},
			allowed: []string{"system/metrics"},
			blocked: []string{"system/logs", "something_else"},
		},
		{
			name: "allows everything",
			matchers: []*stringMatcher{
				{pattern: "*", rule: "allow"},
			},
			allowed: []string{"system/metrics", "system/logs"},
		},
		{
			name: "deny everything",
			matchers: []*stringMatcher{
				{pattern: "*", rule: "deny"},
			},
			blocked: []string{"system/metrics", "system/logs"},
		},
		{
			name: "deny everything with noise",
			matchers: []*stringMatcher{
				{pattern: "*", rule: "deny"},
				{pattern: "something_else", rule: "allow"},
			},
			blocked: []string{"system/metrics", "system/logs"},
		},
		{
			name: "multiple values 1 explicitly allowed",
			matchers: []*stringMatcher{
				{pattern: "system/metrics", rule: "allow"},
			},
			allowed: []string{"system/metrics", "system/logs"},
		},
		{
			name: "filters logstash",
			matchers: []*stringMatcher{
				{pattern: "logstash", rule: "deny"},
			},
			allowed: []string{"elasticsearch"},
			blocked: []string{"logstash"},
		},
		{
			name: "allows logstash only",
			matchers: []*stringMatcher{
				{pattern: "logstash", rule: "allow"},
				{pattern: "*", rule: "deny"},
			},
			allowed: []string{"logstash"},
			blocked: []string{"elasticsearch"},
		},
	}

	for _, tc := range testCases {
		for _, str := range tc.allowed {
			assert.True(t, matchString(str, tc.matchers), "%v: string %q should match test patterns", tc.name, str)
		}
		for _, str := range tc.blocked {
			assert.False(t, matchString(str, tc.matchers), "%v: string %q should not match test patterns", tc.name, str)
		}
	}
}
