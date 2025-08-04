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
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/common"
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
func (e *Downloader) Download(ctx context.Context, a artifact.Artifact, version *agtversion.ParsedSemVer) (download.DownloadResult, error) {
	span, ctx := apm.StartSpan(ctx, "download", "app.internal")
	defer span.End()

	var err error
	downloadResult := download.DownloadResult{}
	downloadedFiles := make([]string, 0, 2)

	defer func() {
		if err != nil {
			for _, path := range downloadedFiles {
				os.Remove(path)
			}
			apm.CaptureError(ctx, err).Send()
		}
	}()

	artifactPathAndName, err := common.GetArtifactPathAndName(a, *version, a.Artifact, e.config.OS(), e.config.Arch(), e.config.TargetDirectory)
	if err != nil {
		return downloadResult, err
	}

	downloadResult.ArtifactPath = artifactPathAndName.ArtifactPath
	downloadResult.ArtifactHashPath = artifactPathAndName.HashPath

	err = e.downloadFile(artifactPathAndName.ArtifactName, artifactPathAndName.ArtifactPath)
	downloadedFiles = append(downloadedFiles, artifactPathAndName.ArtifactPath)
	if err != nil {
		return downloadResult, err
	}

	err = e.downloadFile(artifactPathAndName.HashName, artifactPathAndName.HashPath)
	downloadedFiles = append(downloadedFiles, artifactPathAndName.HashPath)
	if err != nil {
		return downloadResult, err
	}

	return downloadResult, nil
}

func (e *Downloader) downloadFile(filename, fullPath string) error {
	sourcePath := filepath.Join(e.dropPath, filename)

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return errors.New(err, fmt.Sprintf("package '%s' not found", sourcePath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fullPath))
	}
	defer sourceFile.Close()

	if destinationDir := filepath.Dir(fullPath); destinationDir != "" && destinationDir != "." {
		if err := os.MkdirAll(destinationDir, 0755); err != nil {
			return err
		}
	}

	destinationFile, err := os.OpenFile(fullPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, packagePermissions)
	if err != nil {
		return errors.New(err, "creating package file failed", errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fullPath))
	}
	defer destinationFile.Close()

	_, err = e.CopyFunc(destinationFile, sourceFile)
	if err != nil {
		processedErr := e.diskSpaceErrorFunc(err)
		return processedErr
	}

	return nil
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
