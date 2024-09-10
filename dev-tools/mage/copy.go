// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

// Copy copies a file or a directory (recursively) and preserves the permissions.
func Copy(src, dest string) error {
	copy := &CopyTask{Source: src, Dest: dest}
	return copy.Execute()
}

// CopyTask copies a file or directory (recursively) and preserves the permissions.
type CopyTask struct {
	Source   string           // Source directory or file.
	Dest     string           // Destination directory or file.
	Mode     os.FileMode      // Mode to use for copied files. Defaults to preserve permissions.
	DirMode  os.FileMode      // Mode to use for copied dirs. Defaults to preserve permissions.
	Exclude  []string         // Exclude paths that match these regular expressions.
	excludes []*regexp.Regexp // Compiled exclude regexes.
}

// Execute executes the copy and returns an error of there is a failure.
func (t *CopyTask) Execute() error {
	if err := t.init(); err != nil {
		return fmt.Errorf("copy failed: %w", err)
	}

	info, err := os.Stat(t.Source)
	if err != nil {
		return fmt.Errorf("copy failed: cannot stat source file %v: %w", t.Source, err)
	}

	if err := t.recursiveCopy(t.Source, t.Dest, fs.FileInfoToDirEntry(info)); err != nil {
		return fmt.Errorf("copy failed: %w", err)
	}
	return nil
}

func (t *CopyTask) init() error {
	for _, excl := range t.Exclude {
		re, err := regexp.Compile(excl)
		if err != nil {
			return fmt.Errorf("bad exclude pattern %v: %w", excl, err)
		}
		t.excludes = append(t.excludes, re)
	}
	return nil
}

func (t *CopyTask) isExcluded(src string) bool {
	for _, excl := range t.excludes {
		if match := excl.MatchString(filepath.ToSlash(src)); match {
			return true
		}
	}
	return false
}

func (t *CopyTask) recursiveCopy(src, dest string, entry fs.DirEntry) error {
	if entry.IsDir() {
		return t.dirCopy(src, dest, entry)
	}
	return t.fileCopy(src, dest, entry)
}

func (t *CopyTask) fileCopy(src, dest string, entry fs.DirEntry) error {
	if t.isExcluded(src) {
		return nil
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	info, err := entry.Info()
	if err != nil {
		return fmt.Errorf("converting dir entry: %w", err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("failed to copy source file because it is not a regular file")
	}

	mode := t.Mode
	if mode == 0 {
		mode = info.Mode()
	}
	destFile, err := os.OpenFile(createDir(dest),
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode&os.ModePerm)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err = io.Copy(destFile, srcFile); err != nil {
		return err
	}
	return destFile.Close()
}

func (t *CopyTask) dirCopy(src, dest string, entry fs.DirEntry) error {
	if t.isExcluded(src) {
		return nil
	}

	info, err := entry.Info()
	if err != nil {
		return fmt.Errorf("converting dir entry: %w", err)
	}

	mode := t.DirMode
	if mode == 0 {
		mode = info.Mode()
	}

	if err := os.MkdirAll(dest, mode&os.ModePerm); err != nil {
		return fmt.Errorf("failed creating dirs: %w", err)
	}

	contents, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("failed to read dir %v: %w", src, err)
	}

	for _, entry := range contents {
		srcFile := filepath.Join(src, entry.Name())
		destFile := filepath.Join(dest, entry.Name())
		if err = t.recursiveCopy(srcFile, destFile, entry); err != nil {
			return fmt.Errorf("failed to copy %v to %v: %w", srcFile, destFile, err)
		}
	}

	return nil
}
