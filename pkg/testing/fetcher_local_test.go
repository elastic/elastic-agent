package testing

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalFetcher_Fetch(t *testing.T) {
	td := t.TempDir()
	src := filepath.Join(td, "source")
	dst := filepath.Join(td, "destination")

	w, err := os.Create(src)
	require.NoError(t, err)
	w.Write([]byte("testing"))
	w.Close()

	f := LocalFetcher("8.7.0", src)
	require.NoError(t, f.Fetch(context.Background(), runtime.GOOS, runtime.GOARCH, "8.7.0", dst))

	content, err := ioutil.ReadFile(dst)
	require.NoError(t, err)

	assert.Equal(t, []byte("testing"), content)
}

func TestLocalFetcher_Fetch_VersionMismatch(t *testing.T) {
	td := t.TempDir()
	src := filepath.Join(td, "source")
	dst := filepath.Join(td, "destination")

	f := LocalFetcher("8.7.0", src)
	err := f.Fetch(context.Background(), runtime.GOOS, runtime.GOARCH, "8.6.0", dst)
	assert.ErrorIs(t, err, ErrVersionMismatch)
}
