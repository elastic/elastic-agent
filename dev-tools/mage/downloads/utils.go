// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package downloads

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cenkalti/backoff/v4"
	"github.com/gofrs/uuid/v5"
)

// downloadRequest struct contains download details ad path and URL
type downloadRequest struct {
	URL                 string
	DownloadPath        string
	UnsanitizedFilePath string
}

// downloadFile will download a url and store it in a temporary path.
// It writes to the destination file as it downloads it, without
// loading the entire file into memory.
func downloadFile(downloadRequest *downloadRequest) error {
	var filePath string
	if downloadRequest.DownloadPath == "" {
		u, err := uuid.NewV4()
		if err != nil {
			return fmt.Errorf("failed to create UUID: %w", err)
		}
		tempParentDir := filepath.Join(os.TempDir(), u.String())
		err = mkdirAll(tempParentDir)
		if err != nil {
			return fmt.Errorf("creating directory: %w", err)
		}
		u, err = uuid.NewV4()
		if err != nil {
			return fmt.Errorf("failed to create UUID: %w", err)
		}
		filePath = filepath.Join(tempParentDir, u.String())
		downloadRequest.DownloadPath = filePath
	} else {
		u, err := uuid.NewV4()
		if err != nil {
			return fmt.Errorf("failed to create UUID: %w", err)
		}
		filePath = filepath.Join(downloadRequest.DownloadPath, u.String())
	}

	tempFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer tempFile.Close()

	downloadRequest.UnsanitizedFilePath = tempFile.Name()
	exp := getExponentialBackoff(3)

	retryCount := 1
	var fileReader io.Reader
	download := func() error {
		r := httpRequest{URL: downloadRequest.URL}
		bodyStr, err := get(r)
		if err != nil {
			retryCount++
			return fmt.Errorf("downloading file %s: %w", downloadRequest.URL, err)
		}

		fileReader = strings.NewReader(bodyStr)
		return nil
	}

	err = backoff.Retry(download, exp)
	if err != nil {
		return err
	}

	_, err = io.Copy(tempFile, fileReader)
	if err != nil {
		return fmt.Errorf("writing file %s: %w", tempFile.Name(), err)
	}

	_ = os.Chmod(tempFile.Name(), 0666)

	return nil
}
