// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent/pkg/core/process"
)

func createRepoZipArchive(ctx context.Context, dir string, dest string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path to %s: %w", dir, err)
	}
	var stdout bytes.Buffer
	p, err := process.Start("git", process.WithContext(ctx), process.WithArgs([]string{"ls-files", "-z"}), process.WithCmdOptions(attachOut(&stdout), workDir(dir)))
	if err != nil {
		return fmt.Errorf("failed to run git ls-files: %w", err)
	}
	i := <-p.Wait()
	if i.ExitCode() != 0 {
		return fmt.Errorf("failed to run git ls-files: exited code %d", i.ExitCode())
	}
	archive, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", dest, err)
	}
	defer archive.Close()

	zw := zip.NewWriter(archive)
	defer zw.Close()

	s := bufio.NewScanner(&stdout)
	s.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if i := strings.IndexRune(string(data), '\x00'); i >= 0 {
			return i + 1, data[0:i], nil
		}
		if !atEOF {
			return 0, nil, nil
		}
		return len(data), data, bufio.ErrFinalToken
	})
	for s.Scan() {
		if ctx.Err() != nil {
			// incomplete close and delete
			_ = archive.Close()
			_ = os.Remove(dest)
			return ctx.Err()
		}
		err := func(line string) error {
			if line == "" {
				return nil
			}
			fullPath := filepath.Join(absDir, line)
			s, err := os.Stat(fullPath)
			if err != nil {
				return fmt.Errorf("failed to stat file %s: %w", fullPath, err)
			}
			if s.IsDir() {
				// skip directories
				return nil
			}
			f, err := os.Open(fullPath)
			if err != nil {
				return fmt.Errorf("failed to open file %s: %w", fullPath, err)
			}
			defer f.Close()
			w, err := zw.Create(line)
			if err != nil {
				return fmt.Errorf("failed to create zip entry %s: %w", line, err)
			}
			_, err = io.Copy(w, f)
			if err != nil {
				return fmt.Errorf("failed to copy zip entry %s: %w", line, err)
			}
			return nil
		}(s.Text())
		if err != nil {
			return err
		}
	}
	return nil
}

func workDir(dir string) process.CmdOption {
	return func(cmd *exec.Cmd) error {
		cmd.Dir = dir
		return nil
	}
}
