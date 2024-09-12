// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package storage

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReplaceOrRollbackStore(t *testing.T) {
	in := bytes.NewReader([]byte{})

	replaceWith := []byte("new content")
	oldContent := []byte("old content")

	success := NewHandlerStore(func(_ io.Reader) error { return nil })
	failure := NewHandlerStore(func(_ io.Reader) error { return errors.New("fail") })

	t.Run("when the save is successful with target and source don't match", func(t *testing.T) {
		target, err := genFile(t, oldContent)
		require.NoError(t, err)
		dir := filepath.Dir(target)

		requireFilesCount(t, dir, 1)

		s := NewReplaceOnSuccessStore(
			target,
			replaceWith,
			success,
		)

		err = s.Save(in)
		require.NoError(t, err)

		writtenContent, err := os.ReadFile(target)
		require.NoError(t, err)

		require.True(t, bytes.Equal(writtenContent, replaceWith))
		requireFilesCount(t, dir, 2)
		checkPerms(t, target, permMask)
	})

	t.Run("when save is not successful", func(t *testing.T) {
		target, err := genFile(t, oldContent)
		require.NoError(t, err)
		dir := filepath.Dir(target)

		requireFilesCount(t, dir, 1)

		s := NewReplaceOnSuccessStore(
			target,
			replaceWith,
			failure,
		)

		err = s.Save(in)
		require.Error(t, err)

		writtenContent, err := os.ReadFile(target)
		require.NoError(t, err)

		require.True(t, bytes.Equal(writtenContent, oldContent))
		requireFilesCount(t, dir, 1)
	})

	t.Run("when save is successful with target and source content match", func(t *testing.T) {
		target, err := genFile(t, replaceWith)
		require.NoError(t, err)
		dir := filepath.Dir(target)

		requireFilesCount(t, dir, 1)

		s := NewReplaceOnSuccessStore(
			target,
			replaceWith,
			failure,
		)

		err = s.Save(in)
		require.Error(t, err)

		writtenContent, err := os.ReadFile(target)
		require.NoError(t, err)

		require.True(t, bytes.Equal(writtenContent, replaceWith))
		requireFilesCount(t, dir, 1)

	})

	t.Run("when replace is skipped due to target already containing source content", func(t *testing.T) {
		yamlTarget := []byte("fleet:\n  enabled: true\nother: value\n")
		yamlReplaceWith := []byte("#This comment is left out\nfleet:\n  enabled: true\n")
		target, err := genFile(t, yamlTarget)

		require.NoError(t, err)
		dir := filepath.Dir(target)

		requireFilesCount(t, dir, 1)

		s := NewReplaceOnSuccessStore(
			target,
			yamlReplaceWith,
			failure,
		)

		err = s.Save(in)
		require.Error(t, err)

		writtenContent, err := os.ReadFile(target)
		require.NoError(t, err)

		require.True(t, bytes.Equal(writtenContent, yamlTarget))
		requireFilesCount(t, dir, 1)
	})

	t.Run("when target file do not exist", func(t *testing.T) {
		s := NewReplaceOnSuccessStore(
			fmt.Sprintf("%s/%d", os.TempDir(), time.Now().Unix()),
			replaceWith,
			success,
		)
		err := s.Save(in)
		require.Error(t, err)
	})
}

func TestDiskStore(t *testing.T) {
	t.Run("when the target file already exists", func(t *testing.T) {
		target, err := genFile(t, []byte("hello world"))
		require.NoError(t, err)
		d, err := NewDiskStore(target)
		require.NoError(t, err)

		msg := []byte("bonjour la famille")
		err = d.Save(bytes.NewReader(msg))
		require.NoError(t, err)

		content, err := os.ReadFile(target)
		require.NoError(t, err)

		require.Equal(t, msg, content)
		checkPerms(t, target, permMask)
	})

	t.Run("when the target do no exist", func(t *testing.T) {
		dir := t.TempDir()

		target := filepath.Join(dir, "hello.txt")
		d, err := NewDiskStore(target)
		require.NoError(t, err)

		msg := []byte("bonjour la famille")
		err = d.Save(bytes.NewReader(msg))
		require.NoError(t, err)

		content, err := os.ReadFile(target)
		require.NoError(t, err)

		require.Equal(t, msg, content)
		checkPerms(t, target, permMask)
	})

	t.Run("return an io.ReadCloser to the target file", func(t *testing.T) {
		msg := []byte("bonjour la famille")
		target, err := genFile(t, msg)
		require.NoError(t, err)

		d, err := NewDiskStore(target)
		require.NoError(t, err)

		r, err := d.Load()
		require.NoError(t, err)
		defer r.Close()

		content, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, msg, content)
		checkPerms(t, target, permMask)
	})
}

func genFile(t *testing.T, b []byte) (string, error) {
	dir := t.TempDir()

	f, err := os.CreateTemp(dir, "config-")
	if err != nil {
		return "", err
	}
	_, err = f.Write(b)
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		return "", err
	}

	return name, nil
}

func requireFilesCount(t *testing.T, dir string, l int) {
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Equal(t, l, len(files))
}

func checkPerms(t *testing.T, target string, expected os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// Windows API validation of ACL is skipped, as its very complicated.
		return
	}
	info, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, expected, info.Mode())
}
