// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type progConfig struct {
	ErrMessage string
	ExitCode   int
	SleepMS    int
}

const testProgramTemplate = `
package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	if len("{{.ErrMessage}}") > 0 {
		fmt.Fprintf(os.Stderr, "{{.ErrMessage}}")
	}
	if {{.SleepMS}} != 0 {
		time.Sleep(time.Duration({{.SleepMS}})*time.Millisecond)
	}
	if {{.ExitCode}} != 0 {
		os.Exit({{.ExitCode}})
	}
}
`
const testModFile = `
module prog

go 1.18
`

func renderTestProg(cfg progConfig) string {
	t := template.Must(template.New("prog").Parse(testProgramTemplate))
	var b strings.Builder
	err := t.Execute(&b, cfg)
	if err != nil {
		panic(err)
	}
	return b.String()
}

func getExeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func prepareTestProg(ctx context.Context, log *logger.Logger, dir string, cfg progConfig) (string, error) {
	const name = "prog"

	progPath := filepath.Join(dir, name+".go")

	prog := renderTestProg(cfg)
	err := os.WriteFile(progPath, []byte(prog), 0600)
	if err != nil {
		return "", err
	}

	err = os.WriteFile(filepath.Join(dir, "go.mod"), []byte(testModFile), 0600)
	if err != nil {
		return "", err
	}

	err = executeCommand(ctx, log, "go", []string{"build", "-o", dir, progPath}, nil, 0)
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, getExeName(name)), nil
}

func TestExecuteCommand(t *testing.T) {
	log := logp.NewLogger("test_service")

	tests := []struct {
		name    string
		cfg     progConfig
		timeout time.Duration
		wantErr error
	}{
		{
			name: "success",
		},
		{
			name: "fail no error output",
			cfg:  progConfig{"", 1, 0},
		},
		{
			name: "fail with error output",
			cfg:  progConfig{"something failed", 2, 0},
		},
		{
			name:    "fail with timeout",
			cfg:     progConfig{"", 3, 5000}, // executable runs for 5 seconds
			timeout: 100 * time.Millisecond,
			wantErr: context.DeadlineExceeded,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cn := context.WithCancel(context.Background())
			defer cn()

			dir := t.TempDir()

			// Prepare test program with expected param
			exePath, err := prepareTestProg(ctx, log, dir, tc.cfg)
			if err != nil {
				t.Fatal(err)
			}

			err = executeCommand(ctx, log, exePath, nil, nil, tc.timeout)

			if tc.wantErr != nil {
				diff := cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors())
				if diff != "" {
					t.Fatal(diff)
				}
			} else {
				// If exit code is not 0, expect error
				if tc.cfg.ExitCode == 0 {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					if err != nil {
						var exerr *exec.ExitError
						if errors.As(err, &exerr) {
							diff := cmp.Diff(tc.cfg.ExitCode, exerr.ExitCode())
							if diff != "" {
								t.Fatal(diff)
							}
						} else {
							t.Fatalf("want *exec.ExitError, got %T", err)
						}
					} else {
						t.Fatalf("want error code %v, got nil", tc.cfg.ExitCode)
					}
				}
			}

			// Test that we get the proper error message
			// The stderr message is prepended to the err, separated with ':', for example "something failed: exit status 2"
			if err != nil && tc.cfg.ErrMessage != "" {
				arr := strings.Split(err.Error(), ":")
				diff := cmp.Diff(tc.cfg.ErrMessage, arr[0])
				if diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}

}

func TestExecuteCommandErrorLine(t *testing.T) {
	log := logp.NewLogger("test_service")

	tests := []struct {
		name     string
		output   string
		want     string
		wantLast string
	}{
		{
			name:     "last error line is preferred over later lines",
			output:   `2026-01-02 03:04:05: info: A.cpp:1 started\n2026-01-02 03:04:06: error: B.cpp:2 something broke\n2026-01-02 03:04:07: debug: C.cpp:3 cleaning up\n`,
			want:     "2026-01-02 03:04:06: error: B.cpp:2 something broke",
			wantLast: "2026-01-02 03:04:07: debug: C.cpp:3 cleaning up",
		},
		{
			name:     "last line is used without an error line",
			output:   `2026-01-02 03:04:05: info: A.cpp:1 started\n2026-01-02 03:04:07: debug: C.cpp:3 cleaning up\n`,
			want:     "2026-01-02 03:04:07: debug: C.cpp:3 cleaning up",
			wantLast: "2026-01-02 03:04:07: debug: C.cpp:3 cleaning up",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cn := context.WithCancel(context.Background())
			defer cn()

			exePath, err := prepareTestProg(ctx, log, t.TempDir(), progConfig{ErrMessage: tc.output, ExitCode: 1})
			if err != nil {
				t.Fatal(err)
			}

			err = executeCommand(ctx, log, exePath, nil, nil, 0)

			var cmdErr *commandError
			if !errors.As(err, &cmdErr) {
				t.Fatalf("want *commandError, got %T", err)
			}
			if diff := cmp.Diff(tc.want, cmdErr.summary()); diff != "" {
				t.Fatal(diff)
			}
			// The text of the error is still based on the last line of the output.
			if !strings.HasPrefix(err.Error(), tc.wantLast+": ") {
				t.Fatalf("error %q does not start with the last line %q", err.Error(), tc.wantLast)
			}
		})
	}
}
