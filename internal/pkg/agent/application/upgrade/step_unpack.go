// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type UnpackResult struct {
	Hash string `json:"hash" yaml:"hash"`
	// TODO add mapped path of executable
	// agentExecutable string
	versionedHome string `json:"versioned-home" yaml:"versioned-home"`
}

// unpack unpacks archive correctly, skips root (symlink, config...) unpacks data/*
func (u *Upgrader) unpack(version, archivePath, dataDir string) (UnpackResult, error) {
	// unpack must occur in directory that holds the installation directory
	// or the extraction will be double nested
	var unpackRes UnpackResult
	var err error
	if runtime.GOOS == windows {
		unpackRes, err = unzip(u.log, archivePath, dataDir)
	} else {
		unpackRes, err = untar(u.log, version, archivePath, dataDir)
	}

	if err != nil {
		u.log.Errorw("Failed to unpack upgrade artifact", "error.message", err, "version", version, "file.path", archivePath, "unpackResult", unpackRes)
		return UnpackResult{}, err
	}

	u.log.Infow("Unpacked upgrade artifact", "version", version, "file.path", archivePath, "unpackResult", unpackRes)
	return unpackRes, nil
}

func unzip(log *logger.Logger, archivePath, dataDir string) (UnpackResult, error) {
	var hash, rootDir string
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return UnpackResult{}, err
	}
	defer r.Close()

	fileNamePrefix := strings.TrimSuffix(filepath.Base(archivePath), ".zip") + "/" // omitting `elastic-agent-{version}-{os}-{arch}/` in filename

	pm := pathMapper{}
	versionedHome := ""
	manifestFile, err := r.Open("manifest.yaml")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// we got a real error looking up for the manifest
		return UnpackResult{}, fmt.Errorf("looking up manifest in package: %w", err)
	}
	if err == nil {
		// load manifest
		defer manifestFile.Close()
		manifest, err := v1.ParseManifest(manifestFile)
		if err != nil {
			return UnpackResult{}, fmt.Errorf("parsing package manifest: %w", err)
		}
		pm.mappings = manifest.Package.PathMappings
		versionedHome = filepath.Clean(pm.Map(manifest.Package.VersionedHome))
	}

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

		path := filepath.Join(dataDir, strings.TrimPrefix(fileName, "data/"))

		if f.FileInfo().IsDir() {
			log.Debugw("Unpacking directory", "archive", "zip", "file.path", path)
			// remove any world permissions from the directory
			_ = os.MkdirAll(path, f.Mode()&0770)
		} else {
			log.Debugw("Unpacking file", "archive", "zip", "file.path", path)
			// remove any world permissions from the directory/file
			_ = os.MkdirAll(filepath.Dir(path), f.Mode()&0770)
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode()&0770)
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
			return UnpackResult{}, err
		}
	}

	return UnpackResult{
		Hash:          hash,
		versionedHome: versionedHome,
	}, nil
}

func untar(log *logger.Logger, version string, archivePath, dataDir string) (UnpackResult, error) {

	// Look up manifest in the archive and prepare path mappings, if any
	pm := pathMapper{}

	// quickly open the archive and look up manifest.yaml file
	manifestReader, err := getManifestFromTar(archivePath)

	if err != nil {
		return UnpackResult{}, fmt.Errorf("looking for package manifest: %w", err)
	}

	versionedHome := ""
	if manifestReader != nil {
		manifest, err := v1.ParseManifest(manifestReader)
		if err != nil {
			return UnpackResult{}, fmt.Errorf("parsing package manifest: %w", err)
		}

		// set the path mappings
		pm.mappings = manifest.Package.PathMappings
		versionedHome = filepath.Clean(manifest.Package.VersionedHome)
	}

	r, err := os.Open(archivePath)
	if err != nil {
		return UnpackResult{}, errors.New(fmt.Sprintf("artifact for 'elastic-agent' version '%s' could not be found at '%s'", version, archivePath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, archivePath))
	}
	defer r.Close()

	zr, err := gzip.NewReader(r)
	if err != nil {
		return UnpackResult{}, errors.New("requires gzip-compressed body", err, errors.TypeFilesystem)
	}

	tr := tar.NewReader(zr)
	var rootDir string
	var hash string
	fileNamePrefix := getFileNamePrefix(archivePath)

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
			return UnpackResult{}, err
		}

		if !validFileName(f.Name) {
			return UnpackResult{}, errors.New("tar contained invalid filename: %q", f.Name, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, f.Name))
		}

		//get hash
		fileName := strings.TrimPrefix(f.Name, fileNamePrefix)

		if fileName == agentCommitFile {
			hashBytes, err := io.ReadAll(tr)
			if err != nil || len(hashBytes) < hashLen {
				return UnpackResult{}, err
			}

			hash = string(hashBytes[:hashLen])
			continue
		}

		// map the filename
		fileName = pm.Map(fileName)

		// we should check that the path is a local one but since we discard anything that is not under "data/" we can
		// skip the additional check

		// skip everything outside data/
		if !strings.HasPrefix(fileName, "data/") {
			continue
		}

		rel := filepath.FromSlash(strings.TrimPrefix(fileName, "data/"))
		abs := filepath.Join(dataDir, rel)

		// find the root dir
		if currentDir := filepath.Dir(abs); rootDir == "" || len(filepath.Dir(rootDir)) > len(currentDir) {
			rootDir = currentDir
		}

		fi := f.FileInfo()
		mode := fi.Mode()
		switch {
		case mode.IsRegular():
			log.Debugw("Unpacking file", "archive", "tar", "file.path", abs)
			// just to be sure, it should already be created by Dir type
			// remove any world permissions from the directory
			if err = os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
				return UnpackResult{}, errors.New(err, "TarInstaller: creating directory for file "+abs, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, abs))
			}

			// remove any world permissions from the file
			wf, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode.Perm()&0770)
			if err != nil {
				return UnpackResult{}, errors.New(err, "TarInstaller: creating file "+abs, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, abs))
			}

			//nolint:gosec // legacy
			_, err = io.Copy(wf, tr)
			if closeErr := wf.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
			if err != nil {
				return UnpackResult{}, fmt.Errorf("TarInstaller: error writing to %s: %w", abs, err)
			}
		case mode.IsDir():
			log.Debugw("Unpacking directory", "archive", "tar", "file.path", abs)
			// remove any world permissions from the directory
			_, err = os.Stat(abs)
			if errors.Is(err, fs.ErrNotExist) {
				if err := os.MkdirAll(abs, mode.Perm()&0770); err != nil {
					return UnpackResult{}, errors.New(err, "TarInstaller: creating directory for file "+abs, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, abs))
				}
			} else if err != nil {
				return UnpackResult{}, errors.New(err, "TarInstaller: stat() directory for file "+abs, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, abs))
			} else {
				// set the appropriate permissions
				err = os.Chmod(abs, mode.Perm()&0o770)
				if err != nil {
					return UnpackResult{}, errors.New(err, fmt.Sprintf("TarInstaller: setting permissions %O for directory %q", mode.Perm()&0o770, abs), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, abs))
				}
			}
		default:
			return UnpackResult{}, errors.New(fmt.Sprintf("tar file entry %s contained unsupported file type %v", fileName, mode), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fileName))
		}
	}

	return UnpackResult{
		Hash:          hash,
		versionedHome: versionedHome,
	}, nil
}

func getFileNamePrefix(archivePath string) string {
	return strings.TrimSuffix(filepath.Base(archivePath), ".tar.gz") + "/" // omitting `elastic-agent-{version}-{os}-{arch}/` in filename
}

func validFileName(p string) bool {
	if p == "" || strings.Contains(p, `\`) || strings.HasPrefix(p, "/") || strings.Contains(p, "../") {
		return false
	}
	return true
}

type pathMapper struct {
	mappings []map[string]string
}

func (pm pathMapper) Map(path string) string {
	for _, mapping := range pm.mappings {
		for pkgPath, mappedPath := range mapping {
			if strings.HasPrefix(path, pkgPath) {
				return filepath.Join(mappedPath, path[len(pkgPath):])
			}
		}
	}
	return path
}

func getManifestFromTar(archivePath string) (io.Reader, error) {
	r, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("opening package %s: %w", archivePath, err)
	}
	defer r.Close()

	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("package %s does not seem to have a valid gzip compression: %w", archivePath, err)
	}

	tr := tar.NewReader(zr)
	prefix := getFileNamePrefix(archivePath)

	// go through all the content of a tar archive
	// if manifest.yaml is found, read the contents and return a bytereader, nil otherwise ,
	for {
		f, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("reading archive: %w", err)
		}

		fileName := strings.TrimPrefix(f.Name, prefix)
		if fileName == "manifest.yaml" {
			manifestBytes, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("reading manifest bytes: %w", err)
			}

			reader := bytes.NewReader(manifestBytes)
			return reader, nil
		}

	}

	return nil, nil
}
