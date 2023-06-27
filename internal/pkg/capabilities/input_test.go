// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // duplicate code is in test cases
package capabilities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiInput(t *testing.T) {
	t.Run("no match", func(t *testing.T) {
		caps := []*inputCapability{
			{
				Type:  "allow",
				Input: "something_else",
			},
		}
		allowed := []string{"system/metrics", "system/logs"}

		runMultiInputTest(t, caps, allowed, nil)
	})

	t.Run("filters metrics", func(t *testing.T) {
		caps := []*inputCapability{
			{
				Type:  "deny",
				Input: "system/metrics",
			},
		}
		allowed := []string{"system/logs"}
		blocked := []string{"system/metrics"}

		runMultiInputTest(t, caps, allowed, blocked)
	})

	t.Run("allows metrics only", func(t *testing.T) {
		caps := []*inputCapability{
			{
				Type:  "allow",
				Input: "system/metrics",
			},
			{
				Type:  "deny",
				Input: "*",
			},
		}
		allowed := []string{"system/metrics"}
		blocked := []string{"system/logs", "something_else"}

		runMultiInputTest(t, caps, allowed, blocked)
	})

	t.Run("allows everything", func(t *testing.T) {
		caps := []*inputCapability{
			{
				Type:  "allow",
				Input: "*",
			},
		}
		allowed := []string{"system/metrics", "system/logs"}
		runMultiInputTest(t, caps, allowed, nil)
	})

	t.Run("deny everything", func(t *testing.T) {
		caps := []*inputCapability{
			{
				Type:  "deny",
				Input: "*",
			},
		}
		blocked := []string{"system/metrics", "system/logs"}

		runMultiInputTest(t, caps, nil, blocked)
	})

	t.Run("deny everything with noise", func(t *testing.T) {
		caps := []*inputCapability{
			{
				Type:  "deny",
				Input: "*",
			},
			{
				Type:  "allow",
				Input: "something_else",
			},
		}

		blocked := []string{"system/metrics", "system/logs"}
		runMultiInputTest(t, caps, nil, blocked)
	})
}

func TestInput(t *testing.T) {
	t.Run("valid action - 1/1 match", func(t *testing.T) {
		caps := &inputCapability{
			Type:  "allow",
			Input: "system/metrics",
		}

		allowed := []string{"system/metrics"}
		runInputTest(t, caps, allowed, nil)
	})

	t.Run("valid action - 0/1 match", func(t *testing.T) {
		r := &inputCapability{
			Type:  "allow",
			Input: "system/metrics",
		}
		allowed := []string{"system/logs"}

		runInputTest(t, r, allowed, nil)
	})

	t.Run("valid action - deny metrics", func(t *testing.T) {
		r := &inputCapability{
			Type:  "deny",
			Input: "system/metrics",
		}

		allowed := []string{"system/logs"}
		blocked := []string{"system/metrics"}
		runInputTest(t, r, allowed, blocked)
	})

	t.Run("valid action - multiple inputs 1 explicitly allowed", func(t *testing.T) {
		r := &inputCapability{
			Type:  "allow",
			Input: "system/metrics",
		}

		allowed := []string{"system/metrics", "system/logs"}
		runInputTest(t, r, allowed, nil)
	})

}

func runInputTest(t *testing.T, cap *inputCapability, expectAllowed []string, expectBlocked []string) {
	runMultiInputTest(t, []*inputCapability{cap}, expectAllowed, expectBlocked)
}

func runMultiInputTest(t *testing.T, caps []*inputCapability, expectAllowed []string, expectBlocked []string) {
	for _, inputType := range expectAllowed {
		assert.True(t, allowInput(inputType, caps), "input type %v should be allowed", inputType)
	}
	for _, inputType := range expectBlocked {
		assert.False(t, allowInput(inputType, caps), "input type %v should be blocked", inputType)
	}
}
