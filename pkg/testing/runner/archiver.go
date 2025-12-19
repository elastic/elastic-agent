// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
)

func createRepoZipArchive(ctx context.Context, dir string, dest string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path to %s: %w", dir, err)
	}

	archive, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", dest, err)
	}
	defer archive.Close()

	zw := zip.NewWriter(archive)
	defer zw.Close()

	// Archive the main repository files
	err = archiveGitRepo(ctx, zw, absDir, "")
	if err != nil {
		return err
	}

	// Get list of submodules and archive them as well
	submodules, err := getSubmodulePaths(absDir)
	if err != nil {
		return fmt.Errorf("failed to get submodule paths: %w", err)
	}

	for _, submodulePath := range submodules {
		if ctx.Err() != nil {
			_ = archive.Close()
			_ = os.Remove(dest)
			return ctx.Err()
		}
		submoduleAbsPath := filepath.Join(absDir, submodulePath)
		err = archiveGitRepo(ctx, zw, submoduleAbsPath, submodulePath)
		if err != nil {
			return fmt.Errorf("failed to archive submodule %s: %w", submodulePath, err)
		}
	}

	return nil
}

// getSubmodulePaths returns the paths of all submodules (including nested ones) in the repository.
func getSubmodulePaths(repoDir string) ([]string, error) {
	// Use git submodule status --recursive to get all submodules including nested ones
	output, err := cmdBufferedOutput(exec.Command("git", "submodule", "status", "--recursive"), repoDir)
	if err != nil {
		return nil, err
	}

	var submodules []string
	scanner := bufio.NewScanner(&output)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		// Output format: " <sha1> <path> (<describe>)" or "+<sha1> <path> (<describe>)" for modified
		// The path is the second field, after the SHA (which may be prefixed with -, +, or U)
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			submodules = append(submodules, fields[1])
		}
	}

	return submodules, scanner.Err()
}

// archiveGitRepo archives all files (tracked and untracked) from a git repository into the zip writer.
// pathPrefix is prepended to all file paths in the archive (used for submodules).
func archiveGitRepo(ctx context.Context, zw *zip.Writer, repoDir string, pathPrefix string) error {
	projectFilesOutput, err := cmdBufferedOutput(exec.Command("git", "ls-files", "-z"), repoDir)
	if err != nil {
		return err
	}

	// Add files that are not yet tracked in git. Prevents a footcannon where someone writes code to a new file, then tests it before they add to git
	untrackedOutput, err := cmdBufferedOutput(exec.Command("git", "ls-files", "--exclude-standard", "-o", "-z"), repoDir)
	if err != nil {
		return err
	}

	_, err = io.Copy(&projectFilesOutput, &untrackedOutput)
	if err != nil {
		return fmt.Errorf("failed to read stdout of git ls-files -o: %w", err)
	}

	s := bufio.NewScanner(&projectFilesOutput)
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
			return ctx.Err()
		}
		err := func(line string) error {
			if line == "" {
				return nil
			}
			fullPath := filepath.Join(repoDir, line)
			stat, err := os.Stat(fullPath)
			if err != nil {
				return fmt.Errorf("failed to stat file %s: %w", fullPath, err)
			}
			if stat.IsDir() {
				// skip directories
				return nil
			}
			f, err := os.Open(fullPath)
			if err != nil {
				return fmt.Errorf("failed to open file %s: %w", fullPath, err)
			}
			defer f.Close()

			// Combine pathPrefix with the file's relative path for the archive entry
			archivePath := line
			if pathPrefix != "" {
				archivePath = filepath.Join(pathPrefix, line)
			}

			w, err := zw.Create(archivePath)
			if err != nil {
				return fmt.Errorf("failed to create zip entry %s: %w", archivePath, err)
			}
			_, err = io.Copy(w, f)
			if err != nil {
				return fmt.Errorf("failed to copy zip entry %s: %w", archivePath, err)
			}
			return nil
		}(s.Text())
		if err != nil {
			return fmt.Errorf("error adding files: %w", err)
		}
	}
	return nil
}

func cmdBufferedOutput(cmd *exec.Cmd, workDir string) (bytes.Buffer, error) {
	var stdoutBuf bytes.Buffer
	cmd.Dir = workDir
	cmd.Stdout = &stdoutBuf
	err := cmd.Run()
	if err != nil {
		return *bytes.NewBufferString(""), fmt.Errorf("failed to run cmd %s: %w", strings.Join(cmd.Args, " "), err)
	}
	return stdoutBuf, nil
}
