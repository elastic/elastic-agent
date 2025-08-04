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
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
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
func (e *Downloader) Download(ctx context.Context, a artifact.Artifact, version *agtversion.ParsedSemVer) (_ download.DownloadResult, err error) {
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

	// download from source to dest
	path, err := e.download(e.config.OS(), a, *version, "")
	downloadedFiles = append(downloadedFiles, path)
	if err != nil {
		return download.DownloadResult{}, err
	}

	hash, err := e.download(e.config.OS(), a, *version, ".sha512")
	downloadedFiles = append(downloadedFiles, hash)
	if err != nil {
		return download.DownloadResult{}, err
	}

	return download.DownloadResult{
		ArtifactPath: path,
		ArtifactHash: hash,
	}, nil
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
	filename, err := artifact.GetArtifactName(a, version, operatingSystem, e.config.Arch())
	if err != nil {
		return "", errors.New(err, "generating package name failed")
	}

	fullPath, err := artifact.GetArtifactPath(a, version, operatingSystem, e.config.Arch(), e.config.TargetDirectory)
	if err != nil {
		return "", errors.New(err, "generating package path failed")
	}

	if extension != "" {
		filename += extension
		fullPath += extension
	}

	return e.downloadFile(filename, fullPath)
}

func (e *Downloader) downloadFile(filename, fullPath string) (string, error) {
	sourcePath := filepath.Join(e.dropPath, filename)

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return "", errors.New(err, fmt.Sprintf("package '%s' not found", sourcePath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fullPath))
	}
	defer sourceFile.Close()

	if destinationDir := filepath.Dir(fullPath); destinationDir != "" && destinationDir != "." {
		if err := os.MkdirAll(destinationDir, 0755); err != nil {
			return "", err
		}
	}

	destinationFile, err := os.OpenFile(fullPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, packagePermissions)
	if err != nil {
		return "", errors.New(err, "creating package file failed", errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fullPath))
	}
	defer destinationFile.Close()

	_, err = e.CopyFunc(destinationFile, sourceFile)
	if err != nil {
		processedErr := e.diskSpaceErrorFunc(err)
		return fullPath, processedErr
	}

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
