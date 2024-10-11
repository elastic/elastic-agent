// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	goerrors "errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// UnpackResult contains the location and hash of the unpacked agent files
type UnpackResult struct {
	// Hash contains the unpacked agent commit hash, limited to a length of 6 for backward compatibility
	Hash string `json:"hash" yaml:"hash"`
	// VersionedHome indicates the path (relative to topPath, formatted in os-dependent fashion) where to find the unpacked agent files
	// The value depends on the mappings specified in manifest.yaml, if no manifest is found it assumes the legacy data/elastic-agent-<hash> format
	VersionedHome string `json:"versioned-home" yaml:"versioned-home"`
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
		unpackRes, err = untar(u.log, archivePath, dataDir)
	}

	if err != nil {
		u.log.Errorw("Failed to unpack upgrade artifact", "error.message", err, "version", version, "file.path", archivePath, "unpack_result", unpackRes)
		return UnpackResult{}, err
	}

	u.log.Infow("Unpacked upgrade artifact", "version", version, "file.path", archivePath, "unpack_result", unpackRes)
	return unpackRes, nil
}

type packageMetadata struct {
	manifest *v1.PackageManifest
	hash     string
}

func (u *Upgrader) getPackageMetadata(archivePath string) (packageMetadata, error) {
	ext := filepath.Ext(archivePath)
	if ext == ".gz" {
		// if we got gzip extension we need another extension before last
		ext = filepath.Ext(strings.TrimSuffix(archivePath, ext)) + ext
	}

	switch ext {
	case ".zip":
		return getPackageMetadataFromZip(archivePath)
	case ".tar.gz":
		return getPackageMetadataFromTar(archivePath)
	default:
		return packageMetadata{}, fmt.Errorf("unknown package format %q", ext)
	}
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
	var versionedHome string

	metadata, err := getPackageMetadataFromZipReader(r, fileNamePrefix)
	if err != nil {
		return UnpackResult{}, fmt.Errorf("retrieving package metadata from %q: %w", archivePath, err)
	}

	hash = metadata.hash[:hashLen]

	if metadata.manifest != nil {
		pm.mappings = metadata.manifest.Package.PathMappings
		versionedHome = filepath.FromSlash(pm.Map(metadata.manifest.Package.VersionedHome))
	} else {
		// if at this point we didn't load the manifest, set the versioned to the backup value
		versionedHome = createVersionedHomeFromHash(hash)
	}

	unpackFile := func(f *zip.File) (err error) {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if cerr := rc.Close(); cerr != nil {
				err = goerrors.Join(err, cerr)
			}
		}()

		fileName := strings.TrimPrefix(f.Name, fileNamePrefix)
		if fileName == agentCommitFile {
			// we already loaded the hash, skip this one
			return nil
		}

		mappedPackagePath := pm.Map(fileName)

		// skip everything outside data/
		if !strings.HasPrefix(mappedPackagePath, "data/") {
			return nil
		}

		dstPath := strings.TrimPrefix(mappedPackagePath, "data/")
		dstPath = filepath.Join(dataDir, dstPath)

		if f.FileInfo().IsDir() {
			log.Debugw("Unpacking directory", "archive", "zip", "file.path", dstPath)
			// check if the directory already exists
			_, err = os.Stat(dstPath)
			if errors.Is(err, fs.ErrNotExist) {
				// the directory does not exist, create it and any non-existing parent directory with the same permissions
				if err := os.MkdirAll(dstPath, f.Mode().Perm()&0770); err != nil {
					return fmt.Errorf("creating directory %q: %w", dstPath, err)
				}
			} else if err != nil {
				return fmt.Errorf("stat() directory %q: %w", dstPath, err)
			} else {
				// directory already exists, set the appropriate permissions
				err = os.Chmod(dstPath, f.Mode().Perm()&0770)
				if err != nil {
					return fmt.Errorf("setting permissions %O for directory %q: %w", f.Mode().Perm()&0770, dstPath, err)
				}
			}

			_ = os.MkdirAll(dstPath, f.Mode()&0770)
		} else {
			log.Debugw("Unpacking file", "archive", "zip", "file.path", dstPath)
			// create non-existing containing folders with 0770 permissions right now, we'll fix the permission of each
			// directory as we come across them while processing the other package entries
			_ = os.MkdirAll(filepath.Dir(dstPath), 0770)
			f, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode()&0770)
			if err != nil {
				return err
			}
			defer func() {
				if cerr := f.Close(); cerr != nil {
					err = goerrors.Join(err, cerr)
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
		VersionedHome: versionedHome,
	}, nil
}

func getPackageMetadataFromZip(archivePath string) (packageMetadata, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return packageMetadata{}, fmt.Errorf("opening zip archive %q: %w", archivePath, err)
	}
	defer r.Close()
	fileNamePrefix := strings.TrimSuffix(filepath.Base(archivePath), ".zip") + "/" // omitting `elastic-agent-{version}-{os}-{arch}/` in filename
	return getPackageMetadataFromZipReader(r, fileNamePrefix)
}

func getPackageMetadataFromZipReader(r *zip.ReadCloser, fileNamePrefix string) (packageMetadata, error) {
	ret := packageMetadata{}

	// Load manifest, the use of path.Join is intentional since in .zip file paths use slash ('/') as separator
	manifestFile, err := r.Open(path.Join(fileNamePrefix, v1.ManifestFileName))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// we got a real error looking up for the manifest
		return packageMetadata{}, fmt.Errorf("looking up manifest in package: %w", err)
	}

	if err == nil {
		// load manifest
		defer manifestFile.Close()
		ret.manifest, err = v1.ParseManifest(manifestFile)
		if err != nil {
			return packageMetadata{}, fmt.Errorf("parsing package manifest: %w", err)
		}
	}

	// Load hash, the use of path.Join is intentional since in .zip file paths use slash ('/') as separator
	hashFile, err := r.Open(path.Join(fileNamePrefix, agentCommitFile))
	if err != nil {
		// we got a real error looking up for the agent commit file
		return packageMetadata{}, fmt.Errorf("looking up %q in package: %w", agentCommitFile, err)
	}
	defer hashFile.Close()

	hash, err := readCommitHash(hashFile)
	if err != nil {
		return packageMetadata{}, err
	}

	ret.hash = hash

	return ret, nil
}

func untar(log *logger.Logger, archivePath, dataDir string) (UnpackResult, error) {

	var versionedHome string
	var rootDir string
	var hash string

	// Look up manifest in the archive and prepare path mappings, if any
	pm := pathMapper{}

	metadata, err := getPackageMetadataFromTar(archivePath)
	if err != nil {
		return UnpackResult{}, fmt.Errorf("retrieving package metadata from %q: %w", archivePath, err)
	}

	hash = metadata.hash[:hashLen]

	if metadata.manifest != nil {
		// set the path mappings
		pm.mappings = metadata.manifest.Package.PathMappings
		versionedHome = filepath.FromSlash(pm.Map(metadata.manifest.Package.VersionedHome))
	} else {
		// set default value of versioned home if it wasn't set by reading the manifest
		versionedHome = createVersionedHomeFromHash(metadata.hash)
	}

	r, err := os.Open(archivePath)
	if err != nil {
		return UnpackResult{}, errors.New(fmt.Sprintf("artifact for 'elastic-agent' could not be found at '%s'", archivePath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, archivePath))
	}
	defer r.Close()

	zr, err := gzip.NewReader(r)
	if err != nil {
		return UnpackResult{}, errors.New("requires gzip-compressed body", err, errors.TypeFilesystem)
	}

	tr := tar.NewReader(zr)

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

		fileName := strings.TrimPrefix(f.Name, fileNamePrefix)

		if fileName == agentCommitFile {
			// we already loaded the hash, skip this one
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
			// create non-existing containing folders with 0750 permissions right now, we'll fix the permission of each
			// directory as we come across them while processing the other package entries
			if err = os.MkdirAll(filepath.Dir(abs), 0750); err != nil {
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
			// check if the directory already exists
			_, err = os.Stat(abs)
			if errors.Is(err, fs.ErrNotExist) {
				// the directory does not exist, create it and any non-existing parent directory with the same permissions
				if err := os.MkdirAll(abs, mode.Perm()&0770); err != nil {
					return UnpackResult{}, errors.New(err, "TarInstaller: creating directory for file "+abs, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, abs))
				}
			} else if err != nil {
				return UnpackResult{}, errors.New(err, "TarInstaller: stat() directory for file "+abs, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, abs))
			} else {
				// directory already exists, set the appropriate permissions
				err = os.Chmod(abs, mode.Perm()&0770)
				if err != nil {
					return UnpackResult{}, errors.New(err, fmt.Sprintf("TarInstaller: setting permissions %O for directory %q", mode.Perm()&0770, abs), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, abs))
				}
			}
		default:
			return UnpackResult{}, errors.New(fmt.Sprintf("tar file entry %s contained unsupported file type %v", fileName, mode), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fileName))
		}
	}

	return UnpackResult{
		Hash:          hash,
		VersionedHome: versionedHome,
	}, nil
}

func getPackageMetadataFromTar(archivePath string) (packageMetadata, error) {
	// quickly open the archive and look up manifest.yaml file
	fileContents, err := getFilesContentFromTar(archivePath, v1.ManifestFileName, agentCommitFile)
	if err != nil {
		return packageMetadata{}, fmt.Errorf("looking for package metadata files: %w", err)
	}

	ret := packageMetadata{}

	manifestReader, ok := fileContents[v1.ManifestFileName]
	if ok && manifestReader != nil {
		ret.manifest, err = v1.ParseManifest(manifestReader)
		if err != nil {
			return packageMetadata{}, fmt.Errorf("parsing package manifest: %w", err)
		}
	}

	if agentCommitReader, ok := fileContents[agentCommitFile]; ok {
		hash, err := readCommitHash(agentCommitReader)
		if err != nil {
			return packageMetadata{}, err
		}
		ret.hash = hash
	}

	return ret, nil
}

func readCommitHash(reader io.Reader) (string, error) {
	commitBytes, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("reading agent commit hash file: %w", err)
	}
	hash := strings.TrimSpace(string(commitBytes))
	if len(hash) < hashLen {
		return "", fmt.Errorf("hash %q is shorter than minimum length %d", string(commitBytes), hashLen)
	}
	return hash, nil
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

func (pm pathMapper) Map(packagePath string) string {
	for _, mapping := range pm.mappings {
		for pkgPath, mappedPath := range mapping {
			if strings.HasPrefix(packagePath, pkgPath) {
				return path.Join(mappedPath, packagePath[len(pkgPath):])
			}
		}
	}
	return packagePath
}

type tarCloser struct {
	tarFile    *os.File
	gzipReader *gzip.Reader
}

func (tc *tarCloser) Close() error {
	var err error
	if tc.gzipReader != nil {
		err = goerrors.Join(err, tc.gzipReader.Close())
	}
	// prevent double Close() call to fzip reader
	tc.gzipReader = nil
	if tc.tarFile != nil {
		err = goerrors.Join(err, tc.tarFile.Close())
	}
	// prevent double Close() call the underlying file
	tc.tarFile = nil
	return err
}

// openTar is a convenience function to open a tar.gz file.
// It returns a *tar.Reader, an io.Closer implementation to be called to release resources and an error
// In case of errors the *tar.Reader will be nil, but the io.Closer is always returned and must be called also in case
// of errors to close the underlying readers.
func openTar(archivePath string) (*tar.Reader, io.Closer, error) {
	tc := new(tarCloser)
	r, err := os.Open(archivePath)
	if err != nil {
		return nil, tc, fmt.Errorf("opening package %s: %w", archivePath, err)
	}
	tc.tarFile = r

	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, tc, fmt.Errorf("package %s does not seem to have a valid gzip compression: %w", archivePath, err)
	}
	tc.gzipReader = zr

	return tar.NewReader(zr), tc, nil
}

// getFilesContentFromTar is a small utility function which will load in memory the contents of a list of files from the tar archive.
// It's meant to be used to load package information/metadata stored in small files within the .tar.gz archive
func getFilesContentFromTar(archivePath string, files ...string) (map[string]io.Reader, error) {
	tr, tc, err := openTar(archivePath)
	if err != nil {
		return nil, fmt.Errorf("opening tar.gz package %s: %w", archivePath, err)
	}
	defer tc.Close()

	prefix := getFileNamePrefix(archivePath)

	result := make(map[string]io.Reader, len(files))
	fileset := make(map[string]struct{}, len(files))
	// load the fileset with the names we are looking for
	for _, fName := range files {
		fileset[fName] = struct{}{}
	}

	// go through all the content of a tar archive
	// if one of the listed files is found, read the contents and set a byte reader into the result map
	for {
		f, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("reading archive: %w", err)
		}

		fileName := strings.TrimPrefix(f.Name, prefix)
		if _, ok := fileset[fileName]; ok {
			// it's one of the files we are looking for, retrieve the content and set a reader into the result map
			manifestBytes, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("reading manifest bytes: %w", err)
			}

			reader := bytes.NewReader(manifestBytes)
			result[fileName] = reader
		}

	}

	return result, nil
}

// createVersionedHomeFromHash returns a versioned home path relative to topPath in the legacy format `elastic-agent-<hash>`
// formatted using OS-dependent path separators
func createVersionedHomeFromHash(hash string) string {
	return filepath.Join("data", fmt.Sprintf("elastic-agent-%s", hash[:hashLen]))
}
