// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package common

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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

	// piping output of the first command to the second
	// similar to former Makefile implementation
	//
	// go list -m -json all | go run go.elastic.co/go-licence-detector \
	// -includeIndirect \
	// -rules dev-tools/notice/rules.json \
	// -overrides dev-tools/notice/overrides.json \
	// -noticeTemplate dev-tools/notice/NOTICE.txt.tmpl \
	// -noticeOut NOTICE.txt \
	// -depsOut ""
	listCmd := exec.Command("go", "list", "-m", "-json", "all")
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

	return nil
}
