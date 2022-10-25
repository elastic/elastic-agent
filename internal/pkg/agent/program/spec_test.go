// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package program

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
)

func TestSerialization(t *testing.T) {
	spec := Spec{
		Name:     "hello",
		Cmd:      "hellocmd",
		Args:     []string{"-c", "first"},
		Artifact: "nested/hellocmd",
		Rules: transpiler.NewRuleList(
			transpiler.Copy("inputs", "filebeat"),
			transpiler.Filter("filebeat", "output", "keystore"),
			transpiler.Rename("filebeat", "notfilebeat"),
			transpiler.Translate("type", map[string]interface{}{
				"event/file":  "log",
				"event/stdin": "stdin",
			}),
			transpiler.TranslateWithRegexp("type", regexp.MustCompile("^metric/(.+)"), "$1/hello"),
			transpiler.Map("inputs",
				transpiler.Translate("type", map[string]interface{}{
					"event/file": "log",
				})),
			transpiler.FilterValues(
				"inputs",
				"type",
				"log",
			),
		),
		CheckInstallSteps: transpiler.NewStepList(
			transpiler.ExecFile(25, "app", "verify", "--installed"),
		),
		PostInstallSteps: transpiler.NewStepList(
			transpiler.DeleteFile("d-1", true),
			transpiler.MoveFile("m-1", "m-2", false),
		),
		PreUninstallSteps: transpiler.NewStepList(
			transpiler.ExecFile(30, "app", "uninstall", "--force"),
		),
		When:        "1 == 1",
		Constraints: "2 == 2",
	}
	yml := `name: hello
cmd: hellocmd
args:
- -c
- first
artifact: nested/hellocmd
rules:
- copy:
    from: inputs
    to: filebeat
- filter:
    selectors:
    - filebeat
    - output
    - keystore
- rename:
    from: filebeat
    to: notfilebeat
- translate:
    path: type
    mapper:
      event/file: log
      event/stdin: stdin
- translate_with_regexp:
    path: type
    re: ^metric/(.+)
    with: $1/hello
- map:
    path: inputs
    rules:
    - translate:
        path: type
        mapper:
          event/file: log
- filter_values:
    selector: inputs
    key: type
    values:
    - log
check_install:
- exec_file:
    path: app
    args:
    - verify
    - --installed
    timeout: 25
post_install:
- delete_file:
    path: d-1
    fail_on_missing: true
- move_file:
    path: m-1
    target: m-2
    fail_on_missing: false
pre_uninstall:
- exec_file:
    path: app
    args:
    - uninstall
    - --force
    timeout: 30
when: 1 == 1
constraints: 2 == 2
`
	t.Run("serialization", func(t *testing.T) {
		b, err := yaml.Marshal(spec)
		require.NoError(t, err)
		assert.Equal(t, string(b), yml)
	})

	t.Run("deserialization", func(t *testing.T) {
		s := Spec{}
		err := yaml.Unmarshal([]byte(yml), &s)
		require.NoError(t, err)
		assert.Equal(t, spec, s)
	})
}

func TestExport(t *testing.T) {
	dir, err := ioutil.TempDir("", "test_export")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	for _, spec := range Supported {
		b, err := yaml.Marshal(spec)
		require.NoError(t, err)
		err = ioutil.WriteFile(filepath.Join(dir, strings.ToLower(spec.Name)+".yml"), b, 0600)
		require.NoError(t, err)
	}
}

func TestSerializationProcessSettings(t *testing.T) {
	ymlTmpl := `name: "Foobar"
process:
    stop_timeout: %v`

	tests := []struct {
		name  string
		tonum int
		to    time.Duration
	}{
		{"zero", 0, 0},
		{"180ns", 180, 0},
		{"180s", 0, 120 * time.Second},
		{"3m", 0, 3 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				yml         string
				wantTimeout time.Duration
			)
			if tc.to == 0 {
				yml = fmt.Sprintf(ymlTmpl, tc.tonum)
				wantTimeout = time.Duration(tc.tonum)
			} else {
				yml = fmt.Sprintf(ymlTmpl, tc.to)
				wantTimeout = tc.to
			}
			var spec Spec
			err := yaml.Unmarshal([]byte(yml), &spec)
			if err != nil {
				t.Fatal(err)
			}
			diff := cmp.Diff(wantTimeout, spec.Process.StopTimeout)
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
