package upgrade

import (
	"errors"
	goerrors "errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type upgradeCleanup struct {
	log                  *logger.Logger
	symlinkCleanupToggle bool
	archiveCleanupToggle bool
	unpackCleanupToggle  bool
	cleanupFuncs         []func() error
}

func (u *upgradeCleanup) removeFiles(paths ...string) error {
	for _, path := range paths {
		err := os.RemoveAll(path)
		if err != nil {
			return err
		}
	}
	return nil
}

func (u *upgradeCleanup) setupArchiveCleanup(downloadResult download.DownloadResult) error {
	u.log.Debugf("Setting up cleanup for archive, archivePath: %s", downloadResult.ArtifactPath)
	if downloadResult.ArtifactPath == "" || downloadResult.ArtifactHashPath == "" {
		return errors.New("archive path or hash path is empty, cannot cleanup")
	}

	u.archiveCleanupToggle = true

	u.cleanupFuncs = append(u.cleanupFuncs, func() error {
		return u.removeFiles(downloadResult.ArtifactPath, downloadResult.ArtifactHashPath)
	})

	return nil
}

func (u *upgradeCleanup) setupUnpackCleanup(newHomeDir, oldHomeDir string) error {
	u.log.Debugf("Setting up cleanup for unpack, newVersionedHome: %s", newHomeDir)

	if !u.archiveCleanupToggle {
		return errors.New("Cannot setup for unpack cleanup before archive cleanup is setup")
	}

	if newHomeDir == "" || oldHomeDir == "" {
		return errors.New("new or old versioned home is empty, cannot cleanup")
	}

	if newHomeDir == oldHomeDir {
		return errors.New("new and old versioned home are the same, cannot cleanup")
	}

	u.unpackCleanupToggle = true

	u.cleanupFuncs = append(u.cleanupFuncs, func() error {
		return u.removeFiles(newHomeDir)
	})

	return nil
}

type changeSymlinkFunc func(log *logger.Logger, topDirPath, symlinkPath, newTarget string) error

func (u *upgradeCleanup) setupSymlinkCleanup(symlinkFunc changeSymlinkFunc, topDirPath, oldVersionedHome, agentName string) error {
	u.log.Debugf("Setting up cleanup for symlink, topDirPath: %s, oldVersionedHome: %s, agentName: %s", topDirPath, oldVersionedHome, agentName)

	if !u.unpackCleanupToggle {
		return errors.New("Cannot setup for symlink cleanup before unpack cleanup is setup")
	}

	u.symlinkCleanupToggle = true
	oldAgentPath := paths.BinaryPath(filepath.Join(topDirPath, oldVersionedHome), agentName)
	u.log.Infof("oldAgentPath: %s", oldAgentPath)

	u.cleanupFuncs = append(u.cleanupFuncs, func() error {
		err := symlinkFunc(u.log, topDirPath, filepath.Join(topDirPath, agentName), oldAgentPath)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("cleaning up symlink to %q failed: %w", oldAgentPath, err)
		}
		return nil
	})

	return nil
}

func (u *upgradeCleanup) cleanup(err error) error {
	if err == nil {
		u.log.Debugf("No error, skipping cleanup")
		return nil
	}

	slices.Reverse(u.cleanupFuncs)

	for _, cleanupFunc := range u.cleanupFuncs {
		if cleanupErr := cleanupFunc(); cleanupErr != nil {
			return goerrors.Join(err, cleanupErr)
		}
	}

	return err
}
