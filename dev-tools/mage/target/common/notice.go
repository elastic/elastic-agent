// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/magefile/mage/sh"
)

func runCommand(cmd string, args ...string) error {
	s := strings.Join(append([]string{cmd}, args...), " ")
	fmt.Printf(">> %s\n", s)
	err := sh.Run(cmd, args...)
	if err != nil {
		return fmt.Errorf("failed running %s, please fix the issues reported: %w", s, err)
	}
	return nil
}

// Notice Generates NOTICE.txt.
func Notice() (err error) {
	fmt.Println("Generating NOTICE")
	if err := runCommand("go", "mod", "tidy"); err != nil {
		return err
	}
	if err := runCommand("go", "mod", "download"); err != nil {
		return err
	}

	modules, err := getDependentModules()
	if err != nil {
		return fmt.Errorf("unable to fetch list of dependent modules: %w", err)
	}
	slices.Sort(modules)

	// piping output of the first command to the second
	// similar to former Makefile implementation
	//
	// go list -m -json {modules} | go run go.elastic.co/go-licence-detector \
	// -includeIndirect \
	// -rules dev-tools/notice/rules.json \
	// -overrides dev-tools/notice/overrides.json \
	// -noticeTemplate dev-tools/notice/NOTICE.txt.tmpl \
	// -noticeOut NOTICE.txt \
	// -depsOut ""
	listCmdArgs := []string{"list", "-m", "-json"}
	listCmdArgs = append(listCmdArgs, modules...)
	listCmd := exec.Command("go", listCmdArgs...)
	licDetectCmd := exec.Command("go", "run", "go.elastic.co/go-licence-detector",
		"-includeIndirect",
		"-rules", "dev-tools/notice/rules.json",
		"-overrides", "dev-tools/notice/overrides.json",
		"-noticeTemplate", "dev-tools/notice/NOTICE.txt.tmpl",
		"-noticeOut", "NOTICE.txt",
		"-depsOut", "")

	fmt.Printf(">> %s | %s\n", strings.Join(listCmd.Args, " "), strings.Join(licDetectCmd.Args, " "))

	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()

	var buf bytes.Buffer
	listCmd.Stdout = w
	licDetectCmd.Stdin = r
	licDetectCmd.Stderr = &buf

	if err := listCmd.Start(); err != nil {
		return err
	}
	if err := licDetectCmd.Start(); err != nil {
		return err
	}

	if err := listCmd.Wait(); err != nil {
		return err
	}
	w.Close()

	if err := licDetectCmd.Wait(); err != nil {
		// copy error to stdout, helpful if tool failed
		if _, cerr := io.Copy(os.Stdout, &buf); cerr != nil {
			return errors.Join(fmt.Errorf("failed to read stderr: %w", cerr), err)
		}
		return err
	}

	// cat dev-tools/notice/NOTICE.txt.append >> NOTICE.txt
	fmt.Printf(">> %s\n", "cat dev-tools/notice/NOTICE.txt.append >> NOTICE.txt")
	const (
		infn  = "dev-tools/notice/NOTICE.txt.append"
		outfn = "NOTICE.txt"
	)

	f, err := os.Open(infn)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", infn, err)
	}
	defer f.Close()

	out, err := os.OpenFile(outfn, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", outfn, err)
	}

	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()

	if _, err := io.Copy(out, f); err != nil {
		return fmt.Errorf("failed to append file %s: %w", outfn, err)
	}

	// dos2unix NOTICE.txt
	fmt.Printf(">> %s\n", "dos2unix NOTICE.txt")

	content, err := os.ReadFile(outfn)
	if err != nil {
		return fmt.Errorf("failed to read entire file %s: %w", outfn, err)
	}

	// Convert Windows-style line endings to Unix-style
	newContent := strings.ReplaceAll(string(content), "\r\n", "\n")

	err = os.WriteFile(outfn, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to rewrite file using Unix-style line endings %s: %w", outfn, err)
	}

	return nil
}

// getDependentModules returns the unique list paths of modules that the
// github.com/elastic/elastic-agent module recursively depends on. If
// additionalTags are specified, only files that would be compiled with
// those build tags + "linux,darwin,windows" are examined.
// Equivalent to running the following on the command line:
// go list -deps -f "{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}" -tags "linux,darwin,windows,{additionalTags...}"
func getDependentModules(additionalTags ...string) ([]string, error) {
	tags := append([]string{"linux", "darwin", "windows"}, additionalTags...)

	cmdArgs := []string{
		"list",
		"-deps",
		"-f",
		"{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}",
		"-tags",
		strings.Join(tags, ","),
	}

	cmd := exec.Command("go", cmdArgs...)
	fmt.Printf(">> %s\n", strings.Join(cmd.Args, " "))

	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) { // double pointer is necessary because Error() is defined on *exec.ExitError receiver
			fmt.Println(string(exitErr.Stderr))
		}
		return nil, err
	}

	// Parse out list of modules from command output, while also
	// de-duplicating the list.
	modulesMap := map[string]struct{}{}
	for _, line := range bytes.Split(output, []byte("\n")) {
		if len(line) > 0 {
			modulesMap[string(line)] = struct{}{}
		}
	}

	// Convert to list and return
	modules := slices.Collect(maps.Keys(modulesMap))
	return modules, nil
}
