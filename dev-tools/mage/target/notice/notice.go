// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package notice

import (
	"fmt"
	"io"
	"os/exec"
	"sync"

	"github.com/magefile/mage/sh"
)

// Notice regenerates the NOTICE.txt file.
func Notice() error {
	fmt.Println(">> Generating NOTICE")
	fmt.Println(">> fmt - go mod tidy")
	err := sh.RunV("go", "mod", "tidy", "-v")
	if err != nil {
		return fmt.Errorf("failed running go mod tidy, please fix the issues reported: %w", err)
	}
	fmt.Println(">> fmt - go mod download")
	err = sh.RunV("go", "mod", "download")
	if err != nil {
		return fmt.Errorf("failed running go mod download, please fix the issues reported: %w", err)
	}
	fmt.Println(">> fmt - go list")
	str, err := sh.Output("go", "list", "-m", "-json", "all")
	if err != nil {
		return fmt.Errorf("failed running go list, please fix the issues reported: %w", err)
	}
	fmt.Println(">> fmt - go run")
	cmd := exec.Command("go", "run", "go.elastic.co/go-licence-detector", "-includeIndirect", "-rules", "dev-tools/notice/rules.json", "-overrides", "dev-tools/notice/overrides.json", "-noticeTemplate", "dev-tools/notice/NOTICE.txt.tmpl",
		"-noticeOut", "NOTICE.txt")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed running go run, please fix the issues reported: %w", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer stdin.Close()
		defer wg.Done()
		if _, err := io.WriteString(stdin, str); err != nil {
			fmt.Println(err)
		}
	}()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed combined output, please fix the issues reported: %w - %s", err, out)
	}
	wg.Wait()

	return nil
}
