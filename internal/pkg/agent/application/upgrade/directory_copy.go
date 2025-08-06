package upgrade

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/otiai10/copy"
)

type directoryCopier struct {
}

// TODO: add tests for this
// Update to accept copydir function
func (d *directoryCopier) copyActionStore(log *logger.Logger, newHome string) error {
	// copies legacy action_store.yml, state.yml and state.enc encrypted file if exists
	storePaths := []string{paths.AgentActionStoreFile(), paths.AgentStateStoreYmlFile(), paths.AgentStateStoreFile()}
	log.Infow("Copying action store", "new_home_path", newHome)

	for _, currentActionStorePath := range storePaths {
		newActionStorePath := filepath.Join(newHome, filepath.Base(currentActionStorePath))
		log.Infow("Copying action store path", "from", currentActionStorePath, "to", newActionStorePath)
		currentActionStore, err := os.ReadFile(currentActionStorePath)
		if os.IsNotExist(err) {
			// nothing to copy
			continue
		}
		if err != nil {
			return err
		}

		if err := os.WriteFile(newActionStorePath, currentActionStore, 0o600); err != nil {
			return err
		}
	}

	return nil
}

// TODO: add tests for this
// Update to accept copydir function
func (d *directoryCopier) copyRunDirectory(log *logger.Logger, oldRunPath, newRunPath string) error {
	log.Infow("Copying run directory", "new_run_path", newRunPath, "old_run_path", oldRunPath)

	if err := os.MkdirAll(newRunPath, runDirMod); err != nil {
		return errors.New(err, "failed to create run directory")
	}

	err := copyDir(log, oldRunPath, newRunPath, true)
	if os.IsNotExist(err) {
		// nothing to copy, operation ok
		log.Infow("Run directory not present", "old_run_path", oldRunPath)
		return nil
	}
	if err != nil {
		return errors.New(err, "failed to copy %q to %q", oldRunPath, newRunPath)
	}

	return nil
}

func copyDir(l *logger.Logger, from, to string, ignoreErrs bool) error {
	var onErr func(src, dst string, err error) error

	if ignoreErrs {
		onErr = func(src, dst string, err error) error {
			if err == nil {
				return nil
			}

			// ignore all errors, just log them
			l.Infof("ignoring error: failed to copy %q to %q: %s", src, dst, err.Error())
			return nil
		}
	}

	// Try to detect if we are running with SSDs. If we are increase the copy concurrency,
	// otherwise fall back to the default.
	copyConcurrency := 1
	hasSSDs, detectHWErr := install.HasAllSSDs()
	if detectHWErr != nil {
		l.Infow("Could not determine block storage type, disabling copy concurrency", "error.message", detectHWErr)
	}
	if hasSSDs {
		copyConcurrency = runtime.NumCPU() * 4
	}

	return copy.Copy(from, to, copy.Options{
		OnSymlink: func(_ string) copy.SymlinkAction {
			return copy.Shallow
		},
		Sync:         true,
		OnError:      onErr,
		NumOfWorkers: int64(copyConcurrency),
	})
}

func readProcessDirs(runtimeDir string) ([]string, error) {
	pipelines, err := readDirs(runtimeDir)
	if err != nil {
		return nil, err
	}

	processDirs := make([]string, 0)
	for _, p := range pipelines {
		dirs, err := readDirs(p)
		if err != nil {
			return nil, err
		}

		processDirs = append(processDirs, dirs...)
	}

	return processDirs, nil
}

// readDirs returns list of absolute paths to directories inside specified path.
func readDirs(dir string) ([]string, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	dirs := make([]string, 0, len(dirEntries))
	for _, de := range dirEntries {
		if !de.IsDir() {
			continue
		}

		dirs = append(dirs, filepath.Join(dir, de.Name()))
	}

	return dirs, nil
}
