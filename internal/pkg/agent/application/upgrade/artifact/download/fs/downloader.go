// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

const (
	packagePermissions = 0660
)

// Downloader is a downloader able to fetch artifacts from elastic.co web page.
type Downloader struct {
	dropPath           string
	config             *artifact.Config
	diskSpaceErrorFunc func(error) error
	CopyFunc           func(dst io.Writer, src io.Reader) (written int64, err error)
}

// NewDownloader creates and configures Elastic Downloader
func NewDownloader(config *artifact.Config) *Downloader {
	return &Downloader{
		config:             config,
		dropPath:           getDropPath(config),
		diskSpaceErrorFunc: upgradeErrors.ToDiskSpaceErrorFunc(nil),
		CopyFunc:           io.Copy,
	}
}

// Download fetches the package from configured source.
// Returns absolute path to downloaded package and an error.
func (e *Downloader) Download(ctx context.Context, a artifact.Artifact, version *agtversion.ParsedSemVer) (_ string, err error) {
	span, ctx := apm.StartSpan(ctx, "download", "app.internal")
	defer span.End()
	downloadedFiles := make([]string, 0, 2)
	defer func() {
		if err != nil {
			for _, path := range downloadedFiles {
				os.Remove(path)
			}
			apm.CaptureError(ctx, err).Send()
		}
	}()

	fmt.Printf("[FS_DOWNLOADER] Download called for artifact: %+v, version: %s\n", a, version.String())
	fmt.Printf("[FS_DOWNLOADER] Config OS: %s, TargetDirectory: %s\n", e.config.OS(), e.config.TargetDirectory)

	// download from source to dest
	path, err := e.download(e.config.OS(), a, *version, "")
	fmt.Printf("[FS_DOWNLOADER] download() returned path: %s, err: %v\n", path, err)
	downloadedFiles = append(downloadedFiles, path)
	if err != nil {
		return "", err
	}

	// download from source to dest
	hashPath, err := e.download(e.config.OS(), a, *version, ".sha512")
	fmt.Printf("[FS_DOWNLOADER] hash download() returned path: %s, err: %v\n", hashPath, err)
	downloadedFiles = append(downloadedFiles, hashPath)
	if err != nil {
		return "", err
	}

	return path, nil
}

// DownloadAsc downloads the package .asc file from configured source.
// It returns absolute path to the downloaded file and a no-nil error if any occurs.
func (e *Downloader) DownloadAsc(_ context.Context, a artifact.Artifact, version agtversion.ParsedSemVer) (string, error) {
	path, err := e.download(e.config.OS(), a, version, ".asc")
	if err != nil {
		os.Remove(path)
		return "", err
	}

	return path, nil
}

func (e *Downloader) download(
	operatingSystem string,
	a artifact.Artifact,
	version agtversion.ParsedSemVer,
	extension string) (string, error) {
	fmt.Printf("[FS DEBUG] Internal download called: OS=%s, artifact=%+v, version=%+v, ext=%s\n", operatingSystem, a, version, extension)
	filename, err := artifact.GetArtifactName(a, version, operatingSystem, e.config.Arch())
	if err != nil {
		fmt.Printf("[FS DEBUG] Failed to generate filename: %v\n", err)
		return "", errors.New(err, "generating package name failed")
	}
	fmt.Printf("[FS DEBUG] Generated filename: %s\n", filename)

	fullPath, err := artifact.GetArtifactPath(a, version, operatingSystem, e.config.Arch(), e.config.TargetDirectory)
	if err != nil {
		fmt.Printf("[FS DEBUG] Failed to generate path: %v\n", err)
		return "", errors.New(err, "generating package path failed")
	}
	fmt.Printf("[FS DEBUG] Generated fullPath: %s\n", fullPath)

	if extension != "" {
		filename += extension
		fullPath += extension
		fmt.Printf("[FS DEBUG] With extension - filename: %s, fullPath: %s\n", filename, fullPath)
	}

	fmt.Printf("[FS DEBUG] Calling downloadFile with filename=%s, fullPath=%s\n", filename, fullPath)
	return e.downloadFile(filename, fullPath)
}

func (e *Downloader) downloadFile(filename, fullPath string) (string, error) {
	sourcePath := filepath.Join(e.dropPath, filename)
	fmt.Printf("[FS DEBUG] downloadFile called - filename=%s, fullPath=%s\n", filename, fullPath)
	fmt.Printf("[FS DEBUG] dropPath=%s, computed sourcePath=%s\n", e.dropPath, sourcePath)

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		fmt.Printf("[FS DEBUG] Failed to open source file %s: %v\n", sourcePath, err)
		return "", errors.New(err, fmt.Sprintf("package '%s' not found", sourcePath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fullPath))
	}
	defer sourceFile.Close()
	fmt.Printf("[FS DEBUG] Successfully opened source file: %s\n", sourcePath)

	if destinationDir := filepath.Dir(fullPath); destinationDir != "" && destinationDir != "." {
		fmt.Printf("[FS DEBUG] Creating destination directory: %s\n", destinationDir)
		if err := os.MkdirAll(destinationDir, 0755); err != nil {
			fmt.Printf("[FS DEBUG] Failed to create destination directory: %v\n", err)
			return "", err
		}
	}

	fmt.Printf("[FS DEBUG] Creating destination file: %s\n", fullPath)
	destinationFile, err := os.OpenFile(fullPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, packagePermissions)
	if err != nil {
		fmt.Printf("[FS DEBUG] Failed to create destination file: %v\n", err)
		return "", errors.New(err, "creating package file failed", errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fullPath))
	}
	defer destinationFile.Close()

	fmt.Printf("[FS DEBUG] About to call CopyFunc...\n")
	_, err = e.CopyFunc(destinationFile, sourceFile)
	if err != nil {
		fmt.Printf("[FS DEBUG] CopyFunc failed with error: %v\n", err)
		processedErr := e.diskSpaceErrorFunc(err)
		fmt.Printf("[FS DEBUG] diskSpaceErrorFunc processed error: %v -> %v\n", err, processedErr)
		return fullPath, processedErr // Return fullPath so cleanup can remove partial file
	}
	fmt.Printf("[FS DEBUG] CopyFunc succeeded\n")

	return fullPath, nil
}

func getDropPath(cfg *artifact.Config) string {
	// if drop path is not provided fallback to beats subfolder
	if cfg == nil || cfg.DropPath == "" {
		return paths.Downloads()
	}

	// if droppath does not exist fallback to beats subfolder
	stat, err := os.Stat(cfg.DropPath)
	if err != nil || !stat.IsDir() {
		return paths.Downloads()
	}

	return cfg.DropPath
}
