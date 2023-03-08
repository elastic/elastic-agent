package testing

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotFetcher_Fetch(t *testing.T) {
	td := t.TempDir()
	dst := filepath.Join(td, "elastic-agent")
	if runtime.GOOS == "windows" {
		dst = fmt.Sprintf("%s.exe", dst)
	}

	f := SnapshotFetcher()
	require.NoError(t, f.Fetch(context.Background(), runtime.GOOS, runtime.GOARCH, "8.7.0", dst))

	fi, err := os.Stat(dst)
	require.NoError(t, err)

	// is executable
	assert.True(t, fi.Mode()&0111 != 0)
}
