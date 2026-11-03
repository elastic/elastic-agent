// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package gotesthelper contains the helper tests executed by
// TestGoTest_CaptureOutput in dev-tools/mage. They live in a minimal package
// under testdata so that each `go test` run only has to build the standard
// library and testify instead of the whole dev-tools/mage test binary, and so
// that `go test ./...` never picks up these intentionally failing tests.
package gotesthelper

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var gotestHelperMode = os.Getenv("GOTEST_WANT_HELPER") == "1"

func TestGoTest_Helper_OK(t *testing.T) {
	if !gotestHelperMode {
		return
	}

	// Succeeding test without any additional output or test logs.
}

func TestGoTest_Helper_AssertOutput(t *testing.T) {
	if !gotestHelperMode {
		return
	}

	t.Run("assert fails", func(t *testing.T) {
		assert.True(t, false)
	})

	t.Run("assert with message", func(t *testing.T) {
		assert.True(t, false, "My message")
	})

	t.Run("assert with messagef", func(t *testing.T) {
		assert.True(t, false, "My message with arguments: %v", 42)
	})

	t.Run("require fails", func(t *testing.T) {
		require.True(t, false)
	})

	t.Run("require with message", func(t *testing.T) {
		require.True(t, false, "My message")
	})

	t.Run("require with messagef", func(t *testing.T) {
		require.True(t, false, "My message with arguments: %v", 42)
	})

	t.Run("equals map", func(t *testing.T) {
		want := map[string]interface{}{
			"a": 1,
			"b": true,
			"c": "test",
			"e": map[string]interface{}{
				"x": "y",
			},
		}

		got := map[string]interface{}{
			"a": 42,
			"b": false,
			"c": "test",
		}

		assert.Equal(t, want, got)
	})
}

func TestGoTest_Helper_LogOutput(t *testing.T) {
	if !gotestHelperMode {
		return
	}

	t.Run("on error", func(t *testing.T) {
		t.Log("Log message should be printed")
		t.Logf("printf style log message: %v", 42)
		t.Error("Log should fail")
		t.Errorf("Log should fail with printf style log: %v", 23)
	})

	t.Run("on fatal", func(t *testing.T) {
		t.Log("Log message should be printed")
		t.Logf("printf style log message: %v", 42)
		t.Fatal("Log should fail")
	})

	t.Run("on fatalf", func(t *testing.T) {
		t.Log("Log message should be printed")
		t.Logf("printf style log message: %v", 42)
		t.Fatalf("Log should fail with printf style log: %v", 42)
	})

	t.Run("with newlines", func(t *testing.T) {
		t.Log("Log\nmessage\nshould\nbe\nprinted")
		t.Logf("printf\nstyle\nlog\nmessage:\n%v", 42)
		t.Fatalf("Log\nshould\nfail\nwith\nprintf\nstyle\nlog:\n%v", 42)
	})
}

func TestGoTest_Helper_WithPanic(t *testing.T) {
	if !gotestHelperMode {
		return
	}

	panic("Kaputt.")
}

func TestGoTest_Helper_WithWrongPanic(t *testing.T) {
	if !gotestHelperMode {
		return
	}

	t.Run("setup failing go-routine", func(t *testing.T) {
		go func() {
			time.Sleep(1 * time.Second)
			t.Error("oops")
		}()
	})

	t.Run("false positive failure", func(t *testing.T) {
		time.Sleep(10 * time.Second)
	})
}
