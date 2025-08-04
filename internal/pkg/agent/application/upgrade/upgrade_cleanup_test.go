package upgrade

import (
	"errors"
	goerrors "errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/stretchr/testify/require"
)

func newTestCleanup() *upgradeCleanup {
	log, _ := loggertest.New("test")
	return &upgradeCleanup{
		log: log,
	}
}

type mockCleaner struct {
	callOrder []int
}

func (m *mockCleaner) mockCleanupFunc(num int) func() error {
	return func() error {
		m.callOrder = append(m.callOrder, num)
		return nil
	}
}

func TestUpgradeCleanup(t *testing.T) {
	cleaner := newTestCleanup()

	t.Run("should return nil if no error is passed", func(t *testing.T) {
		err := cleaner.cleanup(nil)
		require.NoError(t, err)
	})

	t.Run("when provided with an error, should call the cleanup functions in reverse order", func(t *testing.T) {
		expectedCallOrder := []int{3, 2, 1}
		mockCleanup := mockCleaner{
			callOrder: []int{},
		}

		for i := len(expectedCallOrder) - 1; i >= 0; i-- {
			cleaner.cleanupFuncs = append(cleaner.cleanupFuncs, mockCleanup.mockCleanupFunc(expectedCallOrder[i]))
		}

		err := cleaner.cleanup(errors.New("test error"))
		require.Error(t, err)
		require.Equal(t, expectedCallOrder, mockCleanup.callOrder)
	})

	t.Run("when a cleanup function returns an error, should join the cleanup error with the passed error and immediately return", func(t *testing.T) {
		initialError := errors.New("test error")
		cleanup2Error := errors.New("cleanup 2 error")
		cleanup1Called := false
		cleanupFunc1 := func() error {
			cleanup1Called = true
			return nil
		}

		cleanup2Called := false
		cleanupFunc2 := func() error {
			cleanup2Called = true
			return cleanup2Error
		}

		cleaner.cleanupFuncs = []func() error{cleanupFunc1, cleanupFunc2}

		err := cleaner.cleanup(initialError)
		require.Error(t, err)
		require.Equal(t, goerrors.Join(initialError, cleanup2Error), err, "the error should be the initial error joined with the cleanup error")
		require.False(t, cleanup1Called, "cleanup 1 should not have been called")
		require.True(t, cleanup2Called, "cleanup 2 should have been called")
	})
}

func TestUpgradeCleanup_ArchiveCleanup(t *testing.T) {

	t.Run("when setting up archive cleanup, should return an error if the artifact path is empty", func(t *testing.T) {
		cleaner := newTestCleanup()
		err := cleaner.setupArchiveCleanup(download.DownloadResult{ArtifactHashPath: "test"})
		require.Error(t, err)
		require.Equal(t, "archive path or hash path is empty, cannot cleanup", err.Error())
	})

	t.Run("when setting up archive cleanup, should return an error if the hash path is empty", func(t *testing.T) {
		cleaner := newTestCleanup()
		err := cleaner.setupArchiveCleanup(download.DownloadResult{ArtifactPath: "test"})
		require.Error(t, err)
		require.Equal(t, "archive path or hash path is empty, cannot cleanup", err.Error())
	})

	t.Run("should clean up the archive files", func(t *testing.T) {
		cleaner := newTestCleanup()
		tmpdir := t.TempDir()
		artifactPath := filepath.Join(tmpdir, "test")
		artifactHashPath := filepath.Join(tmpdir, "test.hash")

		err := os.WriteFile(artifactPath, []byte("test"), 0755)
		require.NoError(t, err)
		err = os.WriteFile(artifactHashPath, []byte("test"), 0755)
		require.NoError(t, err)

		downloadResult := download.DownloadResult{
			ArtifactPath:     artifactPath,
			ArtifactHashPath: artifactHashPath,
		}

		err = cleaner.setupArchiveCleanup(downloadResult)
		require.NoError(t, err)
		require.True(t, cleaner.archiveCleanupToggle)

		require.Len(t, cleaner.cleanupFuncs, 1)
		cleanupFunc := cleaner.cleanupFuncs[0]
		err = cleanupFunc()
		require.NoError(t, err)

		_, err = os.Stat(artifactPath)
		require.Error(t, err)
		require.True(t, errors.Is(err, os.ErrNotExist))

		_, err = os.Stat(artifactHashPath)
		require.Error(t, err)
		require.True(t, errors.Is(err, os.ErrNotExist))
	})

	t.Run("should not return an error if files do not exist", func(t *testing.T) {
		cleaner := newTestCleanup()
		tmpdir := t.TempDir()
		artifactPath := filepath.Join(tmpdir, "test")
		artifactHashPath := filepath.Join(tmpdir, "test.hash")

		err := cleaner.setupArchiveCleanup(download.DownloadResult{ArtifactPath: artifactPath, ArtifactHashPath: artifactHashPath})
		require.NoError(t, err)

		_, err = os.Stat(artifactPath)
		require.Error(t, err)
		require.True(t, errors.Is(err, os.ErrNotExist))

		_, err = os.Stat(artifactHashPath)
		require.Error(t, err)
		require.True(t, errors.Is(err, os.ErrNotExist))

		setupFunc := cleaner.cleanupFuncs[0]
		err = setupFunc()
		require.NoError(t, err)
	})
}

func TestUpgradeCleanup_UnpackCleanup(t *testing.T) {

	t.Run("when setting up unpack cleanup, should return an error if the archive cleanup toggle is not set", func(t *testing.T) {
		cleaner := newTestCleanup()
		err := cleaner.setupUnpackCleanup("", "")
		require.Error(t, err)
		require.Equal(t, "Cannot setup for unpack cleanup before archive cleanup is setup", err.Error())
	})

	t.Run("when setting up unpack cleanup, should return an error if the new home dir is empty", func(t *testing.T) {
		cleaner := newTestCleanup()
		cleaner.archiveCleanupToggle = true
		err := cleaner.setupUnpackCleanup("", "test")
		require.Error(t, err)
		require.Equal(t, "new or old versioned home is empty, cannot cleanup", err.Error())
	})

	t.Run("when setting up unpack cleanup, should return an error if the old home dir is empty", func(t *testing.T) {
		cleaner := newTestCleanup()
		cleaner.archiveCleanupToggle = true
		err := cleaner.setupUnpackCleanup("test", "")
		require.Error(t, err)
		require.Equal(t, "new or old versioned home is empty, cannot cleanup", err.Error())
	})

	t.Run("when setting up unpack cleanup, should return an error if the new and old home dirs are the same", func(t *testing.T) {
		cleaner := newTestCleanup()
		cleaner.archiveCleanupToggle = true
		err := cleaner.setupUnpackCleanup("test", "test")
		require.Error(t, err)
	})

	t.Run("should clean up the new home dir", func(t *testing.T) {
		cleaner := newTestCleanup()
		cleaner.archiveCleanupToggle = true
		tmpdir := t.TempDir()
		newHomeDir := filepath.Join(tmpdir, "new")
		oldHomeDir := filepath.Join(tmpdir, "old")

		err := os.MkdirAll(newHomeDir, 0755)
		require.NoError(t, err)
		err = os.MkdirAll(oldHomeDir, 0755)
		require.NoError(t, err)

		err = cleaner.setupUnpackCleanup(newHomeDir, oldHomeDir)
		require.NoError(t, err)

		require.True(t, cleaner.unpackCleanupToggle)

		require.Len(t, cleaner.cleanupFuncs, 1)

		cleanupFunc := cleaner.cleanupFuncs[0]
		err = cleanupFunc()
		require.NoError(t, err)

		_, err = os.Stat(newHomeDir)
		require.Error(t, err)
		require.True(t, errors.Is(err, os.ErrNotExist))

		_, err = os.Stat(oldHomeDir)
		require.NoError(t, err)
	})
}

func TestUpgradeCleanup_SymlinkCleanup(t *testing.T) {
	cleaner := newTestCleanup()
	cleaner.archiveCleanupToggle = true
	cleaner.unpackCleanupToggle = true
	mockSymlinkFunc := func(log *logger.Logger, topDirPath, symlinkPath, newTarget string) error {
		return nil
	}

	t.Run("should return an error if the unpack cleanup toggle is not set", func(t *testing.T) {
		cleaner := newTestCleanup()
		err := cleaner.setupSymlinkCleanup(mockSymlinkFunc, "test", "test", "test")
		require.Error(t, err)
		require.Equal(t, "Cannot setup for symlink cleanup before unpack cleanup is setup", err.Error())
	})

	t.Run("should clean up the symlink", func(t *testing.T) {
		cleaner := newTestCleanup()
		cleaner.archiveCleanupToggle = true
		cleaner.unpackCleanupToggle = true

		calledTopDirPath := ""
		calledSymlinkPath := ""
		calledNewTarget := ""
		mockSymlinkFunc := func(log *logger.Logger, topDirPath, symlinkPath, newTarget string) error {
			calledTopDirPath = topDirPath
			calledSymlinkPath = symlinkPath
			calledNewTarget = newTarget
			return nil
		}

		err := cleaner.setupSymlinkCleanup(mockSymlinkFunc, "mockTopDirPath", "mockSymlinkPath", "mockAgentName")
		require.NoError(t, err)

		cleanupFunc := cleaner.cleanupFuncs[0]
		err = cleanupFunc()
		require.NoError(t, err)

		expectedOldAgentPath := paths.BinaryPath(filepath.Join("mockTopDirPath", "mockSymlinkPath"), "mockAgentName")
		expectedSymlinkPath := filepath.Join("mockTopDirPath", "mockAgentName")

		require.Equal(t, "mockTopDirPath", calledTopDirPath)
		require.Equal(t, expectedSymlinkPath, calledSymlinkPath)
		require.Equal(t, expectedOldAgentPath, calledNewTarget)
	})
}
