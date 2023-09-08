// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// unpack unpacks archive correctly, skips root (symlink, config...) unpacks data/*
func (u *Upgrader) unpack(version, archivePath string) (string, error) {
	// unpack must occur in directory that holds the installation directory
	// or the extraction will be double nested
	var hash string
	var err error
	if runtime.GOOS == windows {
		hash, err = unzip(u.log, archivePath)
	} else {
		hash, err = untar(u.log, version, archivePath)
	}

	if err != nil {
		u.log.Errorw("Failed to unpack upgrade artifact", "error.message", err, "version", version, "file.path", archivePath, "hash", hash)
		return "", err
	}

	u.log.Infow("Unpacked upgrade artifact", "version", version, "file.path", archivePath, "hash", hash)
	return hash, nil
}

func unzip(log *logger.Logger, archivePath string) (string, error) {
	var hash, rootDir string
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", err
	}
	defer r.Close()

	fileNamePrefix := strings.TrimSuffix(filepath.Base(archivePath), ".zip") + "/" // omitting `elastic-agent-{version}-{os}-{arch}/` in filename

	unpackFile := func(f *zip.File) (err error) {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if cerr := rc.Close(); cerr != nil {
				err = multierror.Append(err, cerr)
			}
		}()

		//get hash
		fileName := strings.TrimPrefix(f.Name, fileNamePrefix)
		if fileName == agentCommitFile {
			hashBytes, err := io.ReadAll(rc)
			if err != nil || len(hashBytes) < hashLen {
				return err
			}

			hash = string(hashBytes[:hashLen])
			return nil
		}

		// skip everything outside data/
		if !strings.HasPrefix(fileName, "data/") {
			return nil
		}

		path := filepath.Join(paths.Data(), strings.TrimPrefix(fileName, "data/"))

		if f.FileInfo().IsDir() {
			// TODO: decide if this should be left as log.Debugw, in case log.Infow is too verbose
			log.Infow("Unpacking directory", "archive", "zip", "file.path", path)
			_ = os.MkdirAll(path, f.Mode())
		} else {
			// TODO: decide if this should be left as log.Debugw, in case log.Infow is too verbose
			log.Infow("Unpacking file", "archive", "zip", "file.path", path)
			_ = os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if cerr := f.Close(); cerr != nil {
					err = multierror.Append(err, cerr)
				}
			}()

			//nolint:gosec // legacy
			if _, err = io.Copy(f, rc); err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		if rootDir == "" && filepath.Base(f.Name) == filepath.Dir(f.Name) {
			// skip top level files
			continue
		}
		if currentDir := filepath.Dir(f.Name); rootDir == "" || len(currentDir) < len(rootDir) {
			rootDir = currentDir
		}

		if err := unpackFile(f); err != nil {
			return "", err
		}
	}

	return hash, nil
}

func untar(log *logger.Logger, version string, archivePath string) (string, error) {
	r, err := os.Open(archivePath)
	if err != nil {
		return "", errors.New(fmt.Sprintf("artifact for 'elastic-agent' version '%s' could not be found at '%s'", version, archivePath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, archivePath))
	}
	defer r.Close()

	zr, err := gzip.NewReader(r)
	if err != nil {
		return "", errors.New("requires gzip-compressed body", err, errors.TypeFilesystem)
	}

	tr := tar.NewReader(zr)
	var rootDir string
	var hash string
	fileNamePrefix := strings.TrimSuffix(filepath.Base(archivePath), ".tar.gz") + "/" // omitting `elastic-agent-{version}-{os}-{arch}/` in filename

	// go through all the content of a tar archive
	// if elastic-agent.active.commit file is found, get commit of the version unpacked
	// otherwise copy everything inside data directory (everything related to new version),
	// pieces outside of data we already have and should not be overwritten as they are usually configs
	for {
		f, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}

		if !validFileName(f.Name) {
			return "", errors.New("tar contained invalid filename: %q", f.Name, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, f.Name))
		}

		//get hash
		fileName := strings.TrimPrefix(f.Name, fileNamePrefix)

		if fileName == agentCommitFile {
			hashBytes, err := io.ReadAll(tr)
			if err != nil || len(hashBytes) < hashLen {
				return "", err
			}

			hash = string(hashBytes[:hashLen])
			continue
		}

		// skip everything outside data/
		if !strings.HasPrefix(fileName, "data/") {
			continue
		}

		rel := filepath.FromSlash(strings.TrimPrefix(fileName, "data/"))
		abs := filepath.Join(paths.Data(), rel)

		// find the root dir
		if currentDir := filepath.Dir(abs); rootDir == "" || len(filepath.Dir(rootDir)) > len(currentDir) {
			rootDir = currentDir
		}

		fi := f.FileInfo()
		mode := fi.Mode()
		switch {
		case mode.IsRegular():
			// TODO: decide if this should be left as log.Debugw, in case log.Infow is too verbose
			log.Infow("Unpacking file", "archive", "tar", "file.path", abs)
			// just to be sure, it should already be created by Dir type
			if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
				return "", errors.New(err, "TarInstaller: creating directory for file "+abs, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, abs))
			}

			wf, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode.Perm())
			if err != nil {
				return "", errors.New(err, "TarInstaller: creating file "+abs, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, abs))
			}

			//nolint:gosec // legacy
			_, err = io.Copy(wf, tr)
			if closeErr := wf.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
			if err != nil {
				return "", fmt.Errorf("TarInstaller: error writing to %s: %w", abs, err)
			}
		case mode.IsDir():
			// TODO: decide if this should be left as log.Debugw, in case log.Infow is too verbose
			log.Infow("Unpacking directory", "archive", "tar", "file.path", abs)
			if err := os.MkdirAll(abs, 0755); err != nil {
				return "", errors.New(err, "TarInstaller: creating directory for file "+abs, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, abs))
			}
		default:
			return "", errors.New(fmt.Sprintf("tar file entry %s contained unsupported file type %v", fileName, mode), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fileName))
		}
	}

	return hash, nil
}

func validFileName(p string) bool {
	if p == "" || strings.Contains(p, `\`) || strings.HasPrefix(p, "/") || strings.Contains(p, "../") {
		return false
	}
	return true
}
