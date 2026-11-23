// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/magefile/mage/mg"
	"github.com/stretchr/testify/assert"
)

const envGoTestHelper = "GOTEST_WANT_HELPER"

// TestGoTest_CaptureOutput runs different `go test` scenarios via `GoTest` and
// captures the stderr and stdout output of the test run. The output is then
// validated using a regular expression.
//
// For each scenario a GoTest helper test is defined and a regular expression
// that the test output must match. The naming convention for scenario X is:
//   - TestGoTest_Helper_<X>: the test function to be executed, defined in
//     testdata/gotesthelper/helper_test.go
//   - wantTest<X>: regular expression the output must match.
//
// The helpers live in a minimal package under testdata so each `go test` run
// builds only the standard library and testify instead of linking the whole
// dev-tools/mage test binary, which is very slow on Windows CI runners.
//
// TestGoTest_CaptureOutput sets the `GOTEST_WANT_HELPER` environment variable when it executes the tests.
// each test helper must check if it is driven by this function or not:
//
//	func TestGoTest_Helper_X(t *testing.T) {
//	  if !gotestHelperMode {
//	    return
//	  }
//
//	  // sample test
//	}
func TestGoTest_CaptureOutput(t *testing.T) {
	errNonZero := "go test returned a non-zero value"
	makeArgs := func(test string) GoTestArgs {
		return GoTestArgs{
			LogName:    "asserts",
			Packages:   []string{"./testdata/gotesthelper"},
			Env:        map[string]string{envGoTestHelper: "1"},
			ExtraFlags: []string{"-test.run", test},
		}
	}

	tests := map[string]struct {
		args    GoTestArgs
		verbose bool
		wantErr string
		want    string
	}{
		"passing test without output": {
			args:    makeArgs("TestGoTest_Helper_OK"),
			verbose: true,
			want:    wantTestOK,
		},
		"capture output from assert failures": {
			args:    makeArgs("TestGoTest_Helper_AssertOutput"),
			wantErr: errNonZero,
			want:    wantTestAssertOutput,
		},
		"capture test log output": {
			args:    makeArgs("TestGoTest_Helper_LogOutput"),
			wantErr: errNonZero,
			want:    wantTestLogOutput,
		},
		"capture panic": {
			args:    makeArgs("TestGoTest_Helper_WithPanic"),
			wantErr: errNonZero,
			want:    wantTestWithPanic,
		},
		"capture wrong panic": {
			args:    makeArgs("TestGoTest_Helper_WithWrongPanic"),
			wantErr: errNonZero,
			want:    wantTestWithWrongPanic,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv(mg.VerboseEnv, strconv.FormatBool(test.verbose))

			var buf strings.Builder
			args := test.args
			args.Output = &buf
			err := GoTest(context.TODO(), args)

			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("GoTest did return an unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("GoTest was expected to return an error saying '%v'", test.wantErr)
				}

				errString := err.Error()
				if !strings.Contains(errString, test.wantErr) {
					t.Fatalf("GoTest error does not match expected error message:\nwant: '%v'\ngot: '%v'",
						test.wantErr, errString)
				}
			}

			re, err := regexp.Compile(test.want)
			if err != nil {
				t.Fatalf("Failed to compile test match regex: %v", err)
			}

			output := buf.String()
			if !re.MatchString(output) {
				t.Fatalf("GoTest output mismatch:\nwant:\n%v\n\ngot:\n%v", test.want, output)
			}
		})
	}
}

var wantTestOK = `--- PASS: TestGoTest_Helper_OK.*`

var wantTestAssertOutput = `(?sm:
=== Failed
=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_AssertOutput/assert_fails.*
    .*helper_test.go:\d+:.*
        	Error Trace:	.*helper_test.go:\d+.*
        	Error:      	Should be true.*
        	Test:       	TestGoTest_Helper_AssertOutput/assert_fails.*

=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_AssertOutput/assert_with_message .*
    .*helper_test.go:\d+:.*
        	Error Trace:	.*helper_test.go:\d+.*
        	Error:      	Should be true.*
        	Test:       	TestGoTest_Helper_AssertOutput/assert_with_message.*
        	Messages:   	My message.*

=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_AssertOutput/assert_with_messagef .*
    .*helper_test.go:\d+:.*
        	Error Trace:	.*helper_test.go:\d+.*
        	Error:      	Should be true.*
        	Test:       	TestGoTest_Helper_AssertOutput/assert_with_messagef.*
        	Messages:   	My message with arguments: 42.*

=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_AssertOutput/require_fails .*
    .*helper_test.go:\d+:.*
        	Error Trace:	.*helper_test.go:\d+.*
        	Error:      	Should be true.*
        	Test:       	TestGoTest_Helper_AssertOutput/require_fails.*

=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_AssertOutput/require_with_message .*
    .*helper_test.go:\d+:.*
        	Error Trace:	.*helper_test.go:\d+.*
        	Error:      	Should be true.*
        	Test:       	TestGoTest_Helper_AssertOutput/require_with_message.*
        	Messages:   	My message.*

=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_AssertOutput/require_with_messagef .*
    .*helper_test.go:\d+:.*
        	Error Trace:	.*helper_test.go:\d+.*
        	Error:      	Should be true.*
        	Test:       	TestGoTest_Helper_AssertOutput/require_with_messagef.*
        	Messages:   	My message with arguments: 42.*

=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_AssertOutput/equals_map .*
    .*helper_test.go:\d+:.*
        	Error Trace:	.*helper_test.go:\d+.*
        	Error:      	Not equal:.*
\s+expected: map\[string\]interface \{\}\{"a":1, "b":true, "c":"test", "e":map\[string\]interface \{\}\{"x":"y"\}\}.*
\s+actual  : map\[string\]interface \{\}\{"a":42, "b":false, "c":"test"\}.*
\s+Diff:.*
\s+--- Expected.*
\s+\+\+\+ Actual.*
\s+-\(map\[string\]interface \{\}\) \(len=4\) \{.*
\s+- \(string\) \(len=1\) "a": \(int\) 1,.*
\s+- \(string\) \(len=1\) "b": \(bool\) true,.*
\s+- \(string\) \(len=1\) "c": \(string\) \(len=4\) "test",.*
\s+- \(string\) \(len=1\) "e": \(map\[string\]interface \{\}\) \(len=1\) \{.*
\s+-  \(string\) \(len=1\) "x": \(string\) \(len=1\) "y".*
\s+- }.*
\s+\+\(map\[string\]interface \{\}\) \(len=3\) \{.*
\s+\+ \(string\) \(len=1\) "a": \(int\) 42,.*
\s+\+ \(string\) \(len=1\) "b": \(bool\) false,.*
\s+\+ \(string\) \(len=1\) "c": \(string\) \(len=4\) "test".*
\s+\}.*
)`

var wantTestLogOutput = `(?sm:
=== Failed.*
=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_LogOutput/on_error.*
    helper_test.go:\d+: Log message should be printed.*
    helper_test.go:\d+: printf style log message: 42.*
    helper_test.go:\d+: Log should fail.*
    helper_test.go:\d+: Log should fail with printf style log: 23.*

=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_LogOutput/on_fatal.*
    helper_test.go:\d+: Log message should be printed.*
    helper_test.go:\d+: printf style log message: 42.*
    helper_test.go:\d+: Log should fail.*

=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_LogOutput/on_fatalf.*
    helper_test.go:\d+: Log message should be printed.*
    helper_test.go:\d+: printf style log message: 42.*
    helper_test.go:\d+: Log should fail with printf style log: 42.*

=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_LogOutput/with_newlines.*
    helper_test.go:\d+: Log.*
        message.*
        should.*
        be.*
        printed.*
    helper_test.go:\d+: printf.*
        style.*
        log.*
        message:.*
        42.*
    helper_test.go:\d+: Log.*
        should.*
        fail.*
        with.*
        printf.*
        style.*
        log:.*
        42.*

=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_LogOutput.*

DONE 5 tests, 5 failures in.*
)`

var wantTestWithPanic = `(?sm:
=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_WithPanic.*
panic: Kaputt. \[recovered, repanicked\].*)`

// The regular expression must very forgiving. Unfortunately the order of the
// tests and log lines can differ per run.
var wantTestWithWrongPanic = `(?sm:
=== FAIL: dev-tools/mage/testdata/gotesthelper TestGoTest_Helper_WithWrongPanic.*
.*
panic: Fail in goroutine after TestGoTest_Helper_WithWrongPanic/setup_failing_go-routine has completed.*
)`

func TestMakeGoTestArgsFIPS(t *testing.T) {
	t.Run("FIPS disabled: no FIPS env vars injected", func(t *testing.T) {
		s := DefaultSettings()
		s.Build.FIPSBuild = false

		args := makeGoTestArgs(s, "Unit")

		assert.NotContains(t, args.Tags, "requirefips")
		assert.NotContains(t, args.Env, "GOFIPS140")
		assert.NotContains(t, args.Env, "GODEBUG")
	})

	t.Run("FIPS enabled: requirefips tag added", func(t *testing.T) {
		s := DefaultSettings()
		s.Build.FIPSBuild = true

		args := makeGoTestArgs(s, "Unit")

		assert.Contains(t, args.Tags, "requirefips")
	})

	t.Run("FIPS enabled: compile env from packages.yml propagated", func(t *testing.T) {
		s := DefaultSettings()
		s.Build.FIPSBuild = true

		args := makeGoTestArgs(s, "Unit")

		// packages.yml sets GOFIPS140=v1.0.0 under fips.compile.env;
		// makeGoTestArgs must forward every key from that map.
		assert.Equal(t, "v1.0.0", args.Env["GOFIPS140"])
	})

	t.Run("FIPS enabled: GODEBUG enforces FIPS-only runtime", func(t *testing.T) {
		s := DefaultSettings()
		s.Build.FIPSBuild = true

		args := makeGoTestArgs(s, "Unit")

		assert.Equal(t, "fips140=only,tlsmlkem=0", args.Env["GODEBUG"])
	})
}
