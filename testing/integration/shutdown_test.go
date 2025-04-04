// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
)

func TestGracefullyShutdownComponents(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: Default,
		Local: true,
		Sudo:  false,
	})

	logFilepath := filepath.Join(t.TempDir(), t.Name())
	generateLogFile(t, logFilepath, time.Millisecond*100, 20)

	// We just need a configuration with any Beat that works and
	// we can assert whether the Beat has successfully shutdown,
	// so we borrow the config from TestEventLogFile that uses
	// only Filebeat and ES.
	esURL := startMockES(t, 0, 0, 0, 0)
	cfg := fmt.Sprintf(eventLogConfig, esURL, logFilepath)

	f, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "cannot create fixture from local build")

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	defer cancel()

	// ==================== Prepare
	err = f.Prepare(ctx)
	require.NoError(t, err, "cannot prepare fixture with 'fakeComponent'")

	// ==================== Configure
	if err := f.Configure(ctx, []byte(cfg)); err != nil {
		t.Fatalf("cannot configure Elastic-Agent: %s", err)
	}

	output := strings.Builder{}
	// We use process.Start to ensure it is sending the correct signal
	// proc, err := process.Start(
	// 	f.BinaryPath(),
	// 	process.WithContext(ctx),
	// 	// process.WithArgs([]string{"-e", "-v"}),
	// 	process.WithCmdOptions(func(c *exec.Cmd) error {
	// 		// c.Stderr = &output
	// 		// c.Stdout = &output
	// 		// c.Stderr = os.Stdout
	// 		// c.Stdout = os.Stdout
	// 		c.Stderr = io.Discard
	// 		c.Stdout = io.Discard
	// 		return nil
	// 	}),
	// )
	// if err != nil {
	// 	t.Errorf("failed to start Elastic-Agent process")
	// 	t.Logf("Elastic-Agent output: %s", output.String())
	// }

	cmd, err := f.PrepareAgentCommand(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stdout
	cmd.Stdout = os.Stdout
	cmd.SysProcAttr = getProcAttr()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	fmt.Println("============================== Elastic Agent has started")
	// Wait the Elastic-Agent to be healthy
	healthOutput := strings.Builder{}
	require.Eventuallyf(
		t,
		func() bool {
			if err := f.IsHealthy(ctx); err != nil {
				healthOutput.Reset()
				healthOutput.WriteString(err.Error())
				return false
			}
			return true
		},
		5*time.Minute,
		200*time.Millisecond,
		"Elastic-Agent did not report healthy. Agent status error: '%s'. Process Output: %s",
		&healthOutput, output.String())

	fmt.Println("============================== Elastic Agent is healthy")
	fmt.Println("============================== Sending stop command")
	t.Log("============================== Sending stop command")
	// Stop the Elastic-Agent process and wait for it to return
	// if err := proc.StopWait(); err != nil {
	// 	t.Fatalf(
	// 		"failed to stop Elastic-Agent process: %s. Process output: %s",
	// 		err,
	// 		output.String())
	// }
	if err := stopCmd(cmd); err != nil {
		t.Fatal(err)
	}
	fmt.Println("============================== Stop signal sent")
	if err := cmd.Wait(); err != nil {
		fmt.Println("============================== Error", err)
		t.Fatal(err)
	}
	fmt.Println("============================== Elastic Agent has stopped")
	t.Log("============================== Elastic Agent has stopped")
	assertInLogs(t, f, "elastic-agent", `signal "terminated" received`)
	assertInLogs(t, f, "filestream-default", `Received signal "terminated", stopping`)
	assertInLogs(t, f, "filestream-default", "Stopping filebeat")
	assertInLogs(t, f, "filestream-default", "filebeat stopped.")
}

type elasticAgentLogs struct {
	Log struct {
		Source string `json:"source"`
	} `json:"log"`
	Message string `json:"message"`
}

// assertInLogs search for str as a substring of the message field
// in the log of a component. The component is selected by matching log.source with
// the provided source. If the entry is not found the test fails with an error.
// If found, the message is returned.
//
// The log files searched are the ones in the `logs` folder of the running
// Elastic-Agent from the provided fixture
func assertInLogs(
	t *testing.T,
	f *atesting.Fixture,
	source,
	str string,
) string {
	logs, eventLogs := getLogFileNamesFromFixture(t, f)

	for _, f := range append(logs, eventLogs...) {
		found, msg := findMsgInComponentLogs(t, f, source, str)
		if found {
			return msg
		}
	}

	t.Errorf("%q not found in logs from %q", str, source)
	return ""
}

// findMsgInComponentLogs preforms all the heavy lifting of searching components
// logs in a given file.
// The returned values are a boolean indicating whether the
// str was found, and the message from the log entry.
func findMsgInComponentLogs(
	t *testing.T,
	logfile, source, str string,
) (bool, string) {

	f, err := os.Open(logfile)
	if err != nil {
		t.Fatalf("cannot open file '%s': %s", logfile, err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			t.Logf("could not close log file: %s", err)
		}
	}()

	r := bufio.NewReader(f)
	for {
		data, err := r.ReadBytes('\n')
		entry := elasticAgentLogs{}

		if err != nil {
			if err != io.EOF {
				t.Fatalf("error reading log file '%s': %s", f.Name(), err)
			}
			break
		}

		if err := json.Unmarshal(data, &entry); err != nil {
			t.Fatalf("cannot parse Elastic-Agent logs: %s", err)
		}

		if entry.Log.Source != source {
			continue
		}

		if strings.Contains(entry.Message, str) {
			return true, entry.Message
		}
	}

	return false, ""
}

func getLogFileNamesFromFixture(t *testing.T, f *atesting.Fixture) (logFiles, eventLogFiles []string) {
	basepath := filepath.Join(f.WorkDir(),
		"data",
		"elastic-agent-*",
		"logs")

	logFilesGlob := filepath.Join(basepath, "*.ndjson")
	logFilesPath, err := filepath.Glob(logFilesGlob)
	if err != nil {
		t.Fatalf("could not get log file names:%s", err)
	}

	for _, f := range logFilesPath {
		logFiles = append(logFiles, f)
	}

	eventLogFilesGlob := filepath.Join(basepath, "events", "*.ndjson")
	eventLogFilesPath, err := filepath.Glob(eventLogFilesGlob)
	if err != nil {
		t.Fatalf("could not get log file names:%s", err)
	}

	for _, f := range eventLogFilesPath {
		eventLogFiles = append(eventLogFiles, f)
	}

	return logFiles, eventLogFiles
}

func TestFoo(t *testing.T) {
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	cmd := exec.Command(filepath.Join("simple", "simple"+suffix))
	cmd.Stderr = os.Stdout
	cmd.Stdout = os.Stdout

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// We need to wait for the process to start
	time.Sleep(time.Second)
	t.Log("==================== Started")
	if err := stopCmd(cmd); err != nil {
		t.Fatal("Stop error:", err)
	}
	t.Log("============================== Stop signal sent")

	time.Sleep(2 * time.Second)
	if err := cmd.Wait(); err != nil {
		t.Log("============================== Error", err)
		t.Fatal("Wait failed", err)
	}
	t.Log("============================== Process has stopped")
}
