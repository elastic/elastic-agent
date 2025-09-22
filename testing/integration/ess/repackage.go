// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/dev-tools/mage"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/version"
	agtversion "github.com/elastic/elastic-agent/version"
)

// repackageArchive will take a srcPackage elastic-agent package and create a modified copy that will present parsedNewVersion
// in package version file, manifest and relevant metadata.
func repackageArchive(t *testing.T, srcPackage string, newVersionBuildMetadata string, currentVersion *version.ParsedSemVer, parsedNewVersion *version.ParsedSemVer) (*version.ParsedSemVer, string, error) {
	originalPackageFileName := filepath.Base(srcPackage)

	// integration test fixtures and package names treat the version as a string including the "-SNAPSHOT" suffix
	// while the repackage functions below separate version from the snapshot flag.
	// Normally the early release versions are not snapshots but this test runs on PRs and main branch when we test
	// starting from SNAPSHOT packages, so we have to work around the fact that we cannot simply re-generate the packages
	// by defining versions in 2 separate ways for repackage hack and for fixtures
	buildMetadataForAgentFixture := newVersionBuildMetadata
	if currentVersion.IsSnapshot() {
		buildMetadataForAgentFixture += "-SNAPSHOT"
	}
	versionForFixture := version.NewParsedSemVer(currentVersion.Major(), currentVersion.Minor(), currentVersion.Patch(), "", buildMetadataForAgentFixture)

	// calculate the new package name
	newPackageFileName := strings.Replace(originalPackageFileName, currentVersion.String(), versionForFixture.String(), 1)
	t.Logf("originalPackageName: %q newPackageFileName: %q", originalPackageFileName, newPackageFileName)
	outDir := t.TempDir()
	newPackageAbsPath := filepath.Join(outDir, newPackageFileName)

	// hack the package based on type
	ext := filepath.Ext(originalPackageFileName)
	if ext == ".gz" {
		// fetch the next extension
		ext = filepath.Ext(strings.TrimRight(originalPackageFileName, ext)) + ext
	}
	switch ext {
	case ".zip":
		t.Logf("file %q is a .zip package", originalPackageFileName)
		repackageZipArchive(t, srcPackage, newPackageAbsPath, parsedNewVersion)
	case ".tar.gz":
		t.Logf("file %q is a .tar.gz package", originalPackageFileName)
		repackageTarArchive(t, srcPackage, newPackageAbsPath, parsedNewVersion)
	default:
		t.Logf("unknown extension %q for package file %q ", ext, originalPackageFileName)
		t.FailNow()
	}

	// Create hash file for the new package
	err := mage.CreateSHA512File(newPackageAbsPath)
	require.NoErrorf(t, err, "error creating .sha512 for file %q", newPackageAbsPath)
	return versionForFixture, newPackageAbsPath, err
}

func repackageTarArchive(t *testing.T, srcPackagePath string, newPackagePath string, newVersion *version.ParsedSemVer) {
	oldTopDirectoryName := strings.TrimRight(filepath.Base(srcPackagePath), ".tar.gz")
	newTopDirectoryName := strings.TrimRight(filepath.Base(newPackagePath), ".tar.gz")

	// Open the source package and create readers
	srcPackageFile, err := os.Open(srcPackagePath)
	require.NoErrorf(t, err, "error opening source file %q", srcPackagePath)
	defer func(srcPackageFile *os.File) {
		err := srcPackageFile.Close()
		if err != nil {
			assert.Failf(t, "error closing source file %q: %v", srcPackagePath, err)
		}
	}(srcPackageFile)

	gzReader, err := gzip.NewReader(srcPackageFile)
	require.NoErrorf(t, err, "error creating gzip reader for file %q", srcPackagePath)
	defer func(gzReader *gzip.Reader) {
		err := gzReader.Close()
		if err != nil {
			assert.Failf(t, "error closing gzip reader for source file %q: %v", srcPackagePath, err)
		}
	}(gzReader)

	tarReader := tar.NewReader(gzReader)

	// Create the output file and its writers
	newPackageFile, err := os.OpenFile(newPackagePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o750)
	require.NoErrorf(t, err, "error opening output file %q", newPackagePath)
	defer func(newPackageFile *os.File) {
		err := newPackageFile.Close()
		if err != nil {
			assert.Failf(t, "error closing output file %q: %v", newPackagePath, err)
		}
	}(newPackageFile)

	gzWriter := gzip.NewWriter(newPackageFile)
	defer func(gzWriter *gzip.Writer) {
		err := gzWriter.Close()
		if err != nil {
			assert.Failf(t, "error closing gzip writer for file %q: %v", newPackagePath, err)
		}
	}(gzWriter)

	tarWriter := tar.NewWriter(gzWriter)
	defer func(tarWriter *tar.Writer) {
		err := tarWriter.Close()
		if err != nil {
			assert.Failf(t, "error closing tar writer for file %q: %v", newPackagePath, err)
		}
	}(tarWriter)

	hackTarGzPackage(t, tarReader, tarWriter, oldTopDirectoryName, newTopDirectoryName, newVersion)
}

func hackTarGzPackage(t *testing.T, reader *tar.Reader, writer *tar.Writer, oldTopDirName string, newTopDirName string, newVersion *version.ParsedSemVer) {

	for {
		f, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "error reading source package")

		// tar format uses forward slash as path separator, make sure we use only "path" package for checking and manipulation
		switch path.Base(f.Name) {
		case v1.ManifestFileName:
			// read old content and generate the new manifest based on that
			newManifest := generateNewManifestContent(t, reader, newVersion)
			newManifestBytes := []byte(newManifest)

			// fix file length in header
			writeModifiedTarHeader(t, writer, f, oldTopDirName, newTopDirName, int64(len(newManifestBytes)))

			// write the new manifest body
			_, err = writer.Write(newManifestBytes)
			require.NoError(t, err, "error writing out modified manifest")

		case agtversion.PackageVersionFileName:

			t.Logf("writing new package version: %q", newVersion.String())

			// new package version file contents
			newPackageVersionBytes := []byte(newVersion.String())
			// write new header
			writeModifiedTarHeader(t, writer, f, oldTopDirName, newTopDirName, int64(len(newPackageVersionBytes)))
			// write content
			_, err := writer.Write(newPackageVersionBytes)
			require.NoError(t, err, "error writing out modified package version")
		default:
			// write entry header with the size untouched
			writeModifiedTarHeader(t, writer, f, oldTopDirName, newTopDirName, f.Size)

			// copy body
			_, err := io.Copy(writer, reader)
			require.NoErrorf(t, err, "error writing file content for %+v", f)
		}

	}

}

func writeModifiedTarHeader(t *testing.T, writer *tar.Writer, header *tar.Header, oldTopDirName, newTopDirName string, size int64) {
	// replace top dir in the path
	header.Name = strings.Replace(header.Name, oldTopDirName, newTopDirName, 1)
	header.Size = size

	err := writer.WriteHeader(header)
	require.NoErrorf(t, err, "error writing tar header %+v", header)
}

func repackageZipArchive(t *testing.T, srcPackagePath string, newPackagePath string, newVersion *version.ParsedSemVer) {
	oldTopDirectoryName := strings.TrimRight(filepath.Base(srcPackagePath), ".zip")
	newTopDirectoryName := strings.TrimRight(filepath.Base(newPackagePath), ".zip")

	// Open the source package and create readers
	zipReader, err := zip.OpenReader(srcPackagePath)
	require.NoErrorf(t, err, "error opening source file %q", srcPackagePath)
	defer func(zipReader *zip.ReadCloser) {
		err := zipReader.Close()
		if err != nil {
			assert.Failf(t, "error closing source file %q: %v", srcPackagePath, err)
		}
	}(zipReader)

	// Create the output file and its writers
	newPackageFile, err := os.OpenFile(newPackagePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o750)
	require.NoErrorf(t, err, "error opening output file %q", newPackagePath)
	defer func(newPackageFile *os.File) {
		err := newPackageFile.Close()
		if err != nil {
			assert.Failf(t, "error closing output file %q: %v", newPackagePath, err)
		}
	}(newPackageFile)

	zipWriter := zip.NewWriter(newPackageFile)
	defer func(zipWriter *zip.Writer) {
		err := zipWriter.Close()
		if err != nil {
			assert.Failf(t, "error closing zip writer for output file %q: %v", newPackagePath, err)
		}
	}(zipWriter)

	hackZipPackage(t, zipReader, zipWriter, oldTopDirectoryName, newTopDirectoryName, newVersion)
}

func hackZipPackage(t *testing.T, reader *zip.ReadCloser, writer *zip.Writer, oldTopDirName string, newTopDirName string, newVersion *version.ParsedSemVer) {
	for _, zippedFile := range reader.File {
		zippedFileHeader := zippedFile.FileHeader

		// zip format uses forward slash as path separator, make sure we use only "path" package for checking and manipulation
		switch path.Base(zippedFile.Name) {
		case v1.ManifestFileName:
			// read old content
			manifestReader, err := zippedFile.Open()
			require.NoError(t, err, "error opening manifest file in zipped package")

			// generate new manifest based on the old manifest and the new version
			newManifest := generateNewManifestContent(t, manifestReader, newVersion)

			// we need to close the file content reader
			err = manifestReader.Close()
			require.NoError(t, err, "error closing manifest file in zipped package")

			newManifestBytes := []byte(newManifest)
			fileContentWriter := writeModifiedZipFileHeader(t, writer, zippedFileHeader, oldTopDirName, newTopDirName, uint64(len(newManifest)))

			_, err = io.Copy(fileContentWriter, bytes.NewReader(newManifestBytes))
			require.NoError(t, err, "error writing out modified manifest")

		case agtversion.PackageVersionFileName:
			t.Logf("writing new package version: %q", newVersion.String())
			// new package version file contents
			newPackageVersionBytes := []byte(newVersion.String())
			fileContentWriter := writeModifiedZipFileHeader(t, writer, zippedFileHeader, oldTopDirName, newTopDirName, uint64(len(newPackageVersionBytes)))

			_, err := io.Copy(fileContentWriter, bytes.NewReader(newPackageVersionBytes))
			require.NoError(t, err, "error writing out modified package version")
		default:
			// write entry header with the size untouched
			fileContentWriter := writeModifiedZipFileHeader(t, writer, zippedFileHeader, oldTopDirName, newTopDirName, zippedFile.UncompressedSize64)
			fileContentReader, err := zippedFile.Open()
			require.NoErrorf(t, err, "error opening zip file content reader for %+v", zippedFileHeader)
			// copy body
			_, err = io.Copy(fileContentWriter, fileContentReader)
			require.NoErrorf(t, err, "error writing file content for %+v", zippedFileHeader)

			// we need to close the file content reader
			err = fileContentReader.Close()
			require.NoError(t, err, "error closing zipped file writer for %+v", zippedFileHeader)
		}
	}
}

func writeModifiedZipFileHeader(t *testing.T, writer *zip.Writer, header zip.FileHeader, oldTopDirName, newTopDirName string, size uint64) io.Writer {
	header.Name = strings.Replace(header.Name, oldTopDirName, newTopDirName, 1)
	header.UncompressedSize64 = size
	fileContentWriter, err := writer.CreateHeader(&header)
	require.NoErrorf(t, err, "error creating header for %+v", header)
	return fileContentWriter
}

func generateNewManifestContent(t *testing.T, manifestReader io.Reader, newVersion *version.ParsedSemVer) string {
	oldManifest, err := v1.ParseManifest(manifestReader)
	require.NoError(t, err, "reading manifest content from tar source archive")

	t.Logf("read old manifest: %+v", oldManifest)

	// replace manifest content
	newManifest, err := mage.GeneratePackageManifest("elastic-agent", newVersion.String(), oldManifest.Package.Snapshot, oldManifest.Package.Hash, oldManifest.Package.Hash[:6], oldManifest.Package.Fips, nil)
	require.NoErrorf(t, err, "GeneratePackageManifest(%v, %v, %v, %v, %v) failed", newVersion.String(), oldManifest.Package.Snapshot, oldManifest.Package.Hash, oldManifest.Package.Hash[:6], nil)

	t.Logf("generated new manifest:\n%s", newManifest)
	return newManifest
}
