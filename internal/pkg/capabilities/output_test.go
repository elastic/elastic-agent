// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // duplicate code is in test cases
package capabilities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiOutput(t *testing.T) {
	t.Run("no match", func(t *testing.T) {
		caps := []*outputCapability{
			{
				Type:   "allow",
				Output: "something_else",
			},
		}

		allowed := []string{"elasticsearch", "logstash"}
		runMultiOutputTest(t, caps, allowed, nil)
	})

	t.Run("filters logstash", func(t *testing.T) {
		caps := []*outputCapability{
			{
				Type:   "deny",
				Output: "logstash",
			},
		}

		allowed := []string{"elasticsearch"}
		blocked := []string{"logstash"}
		runMultiOutputTest(t, caps, allowed, blocked)
	})

	t.Run("allows logstash only", func(t *testing.T) {
		caps := []*outputCapability{
			{
				Type:   "allow",
				Output: "logstash",
			},
			{
				Type:   "deny",
				Output: "*",
			},
		}

		blocked := []string{"elasticsearch"}
		allowed := []string{"logstash"}
		runMultiOutputTest(t, caps, allowed, blocked)
	})

	t.Run("allows everything", func(t *testing.T) {
		caps := []*outputCapability{
			{
				Type:   "allow",
				Output: "*",
			},
		}

		allowed := []string{"elasticsearch", "logstash"}
		runMultiOutputTest(t, caps, allowed, nil)
	})

	t.Run("deny everything", func(t *testing.T) {
		caps := []*outputCapability{
			{
				Type:   "deny",
				Output: "*",
			},
		}

		blocked := []string{"elasticsearch", "logstash"}
		runMultiOutputTest(t, caps, nil, blocked)
	})
}

func TestOutput(t *testing.T) {

	t.Run("valid action - 1/1 match", func(t *testing.T) {
		r := &outputCapability{
			Type:   "allow",
			Output: "logstash",
		}

		allowed := []string{"logstash"}
		runOutputTest(t, r, allowed, nil)
	})

	t.Run("valid action - 0/1 match", func(t *testing.T) {
		r := &outputCapability{
			Type:   "allow",
			Output: "elasticsearch",
		}

		allowed := []string{"logstash"}
		runOutputTest(t, r, allowed, nil)
	})

	t.Run("valid action - deny logstash", func(t *testing.T) {
		r := &outputCapability{
			Type:   "deny",
			Output: "logstash",
		}

		blocked := []string{"logstash"}
		allowed := []string{"elasticsearch"}
		runOutputTest(t, r, allowed, blocked)
	})

	t.Run("valid action - multiple outputs 1 explicitly allowed", func(t *testing.T) {
		r := &outputCapability{
			Type:   "allow",
			Output: "logstash",
		}

		allowed := []string{"logstash", "elasticsearch"}
		runOutputTest(t, r, allowed, nil)
	})
}

func runMultiOutputTest(t *testing.T, caps []*outputCapability, expectAllowed []string, expectBlocked []string) {
	for _, outputType := range expectAllowed {
		assert.True(t, allowOutput(outputType, caps), "expected output type %v to be allowed", outputType)
	}
	for _, outputType := range expectBlocked {
		assert.False(t, allowOutput(outputType, caps), "expected output type %v to be blocked", outputType)
	}
}

func runOutputTest(t *testing.T, r *outputCapability, expectAllowed []string, expectBlocked []string) {
	runMultiOutputTest(t, []*outputCapability{r}, expectAllowed, expectBlocked)
}
