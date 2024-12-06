package cmd

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestGetFileOwnerUnix(t *testing.T) {
	path := t.TempDir()
	fp := filepath.Join(path, "testfile")
	_, err := os.Create(fp)
	require.NoError(t, err)

	cu := os.Geteuid()

	fo, err := getFileOwner(fp)
	require.NoError(t, err)

	require.Equal(t, fo, strconv.Itoa(cu))
}

func TestIsOwnerUnix(t *testing.T) {
	path := t.TempDir()
	fp := filepath.Join(path, "testfile")
	_, err := os.Create(fp)
	require.NoError(t, err)

	err = unix.Setuid(100)
	require.NoError(t, err)
}
