// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fs

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

const (
	packagePermissions = 0660
)

// Downloader is a downloader able to fetch artifacts from elastic.co web page.
type Downloader struct {
	dropPath string
	config   *artifact.Config
	// The following are abstractions for stdlib functions so that we can mock them in tests.
	copy     func(dst io.Writer, src io.Reader) (int64, error)
	mkdirAll func(name string, perm os.FileMode) error
	openFile func(name string, flag int, perm os.FileMode) (*os.File, error)
}

// NewDownloader creates and configures Elastic Downloader
func NewDownloader(config *artifact.Config) *Downloader {
	return &Downloader{
		config:   config,
		dropPath: getDropPath(config),
		copy:     io.Copy,
		mkdirAll: os.MkdirAll,
		openFile: os.OpenFile,
	}
}

// Download fetches the package from configured source.
// Returns absolute path to downloaded package and an error.
func (e *Downloader) Download(ctx context.Context, _ artifact.Artifact, filename, sourceDir, targetDir string) (_ string, err error) {
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

	var sourcePath string
	if strings.HasPrefix(sourceDir, "http://") || strings.HasPrefix(sourceDir, "https://") {
		sourcePath = filepath.Join(getDropPath(e.config), filename)
	} else {
		sourcePath = filepath.Join(strings.TrimPrefix(sourceDir, "file://"), filename)
	}
	targetPath := filepath.Join(targetDir, filename)

	path, err := e.download(sourcePath, targetPath)
	downloadedFiles = append(downloadedFiles, path)
	if err != nil {
		return "", err
	}

	hashPath, err := e.download(sourcePath+".sha512", targetPath+".sha512")
	downloadedFiles = append(downloadedFiles, hashPath)
	return path, err
}

func (e *Downloader) download(sourcePath, targetPath string) (string, error) {
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return "", errors.New(err, fmt.Sprintf("package '%s' not found", sourcePath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, targetPath))
	}
	defer sourceFile.Close()

	if destinationDir := filepath.Dir(targetPath); destinationDir != "" && destinationDir != "." {
		if err := e.mkdirAll(destinationDir, 0755); err != nil {
			return "", err
		}
	}

	destinationFile, err := e.openFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, packagePermissions)
	if err != nil {
		return "", goerrors.Join(errors.New("creating package file failed", errors.TypeFilesystem, errors.M(errors.MetaKeyPath, targetPath)), err)
	}
	defer destinationFile.Close()

	_, err = e.copy(destinationFile, sourceFile)
	if err != nil {
		return targetPath, err
	}

	return targetPath, nil
}

func getDropPath(cfg *artifact.Config) string {
	// if drop path is not provided fallback to beats subfolder
	if cfg == nil || cfg.DropPath == "" {
		return paths.Downloads()
	}

	// if droppath does not exist fallback to beats subfolder
	stat, err := os.Stat(filepath.Clean(cfg.DropPath))
	if err != nil || !stat.IsDir() {
		return paths.Downloads()
	}

	return cfg.DropPath
}
