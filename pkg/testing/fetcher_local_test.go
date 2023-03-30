// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testing

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalFetcher_Name(t *testing.T) {
	f := LocalFetcher(t.TempDir())
	require.Equal(t, "local", f.Name())
}

func TestLocalFetcher_IgnoresSnapshot(t *testing.T) {
	td := t.TempDir()

	suffix, err := GetPackageSuffix(runtime.GOOS, runtime.GOARCH)
	require.NoError(t, err)

	snapshotPath := fmt.Sprintf("elastic-agent-8.7.0-SNAPSHOT-%s", suffix)
	notSnapshotPath := fmt.Sprintf("elastic-agent-8.7.0-%s", suffix)
	require.NoError(t, ioutil.WriteFile(filepath.Join(td, snapshotPath), []byte("snapshot contents"), 0644))
	require.NoError(t, ioutil.WriteFile(filepath.Join(td, notSnapshotPath), []byte("not snapshot contents"), 0644))

	f := LocalFetcher(td)

	tmp := t.TempDir()
	res, err := f.Fetch(context.Background(), runtime.GOOS, runtime.GOARCH, "8.7.0")
	require.NoError(t, err)

	err = res.Fetch(context.Background(), t, tmp)
	require.NoError(t, err)
	content, err := ioutil.ReadFile(filepath.Join(tmp, res.Name()))
	require.NoError(t, err)

	assert.Equal(t, []byte("not snapshot contents"), content)
}

func TestLocalFetcher_SnapshotFirst(t *testing.T) {
	td := t.TempDir()

	suffix, err := GetPackageSuffix(runtime.GOOS, runtime.GOARCH)
	require.NoError(t, err)

	snapshotPath := fmt.Sprintf("elastic-agent-8.7.0-SNAPSHOT-%s", suffix)
	notSnapshotPath := fmt.Sprintf("elastic-agent-8.7.0-%s", suffix)
	require.NoError(t, ioutil.WriteFile(filepath.Join(td, snapshotPath), []byte("snapshot contents"), 0644))
	require.NoError(t, ioutil.WriteFile(filepath.Join(td, notSnapshotPath), []byte("not snapshot contents"), 0644))

	f := LocalFetcher(td, WithLocalSnapshotOnly())

	tmp := t.TempDir()
	res, err := f.Fetch(context.Background(), runtime.GOOS, runtime.GOARCH, "8.7.0")
	require.NoError(t, err)

	err = res.Fetch(context.Background(), t, tmp)
	require.NoError(t, err)
	content, err := ioutil.ReadFile(filepath.Join(tmp, res.Name()))
	require.NoError(t, err)

	assert.Equal(t, []byte("snapshot contents"), content)
}
