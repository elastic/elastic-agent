// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package downloads

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
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
		tempParentDir := filepath.Join(os.TempDir(), uuid.NewString())
		err := mkdirAll(tempParentDir)
		if err != nil {
			return fmt.Errorf("creating directory: %w", err)
		}
		filePath = filepath.Join(tempParentDir, uuid.NewString())
		downloadRequest.DownloadPath = filePath
	} else {
		filePath = filepath.Join(downloadRequest.DownloadPath, uuid.NewString())
	}

	tempFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer tempFile.Close()

	downloadRequest.UnsanitizedFilePath = tempFile.Name()
	exp := getExponentialBackoff(3)

	retryCount := 1
	var fileReader io.ReadCloser
	download := func() error {
		resp, err := http.Get(downloadRequest.URL)
		if err != nil {
			retryCount++
			return fmt.Errorf("downloading file %s: %w", downloadRequest.URL, err)
		}

		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return backoff.Permanent(fmt.Errorf("%s not found", downloadRequest.URL))
		}

		fileReader = resp.Body

		return nil
	}

	err = backoff.Retry(download, exp)
	if err != nil {
		return err
	}
	defer fileReader.Close()

	_, err = io.Copy(tempFile, fileReader)
	if err != nil {
		return fmt.Errorf("writing file %s: %w", tempFile.Name(), err)
	}

	_ = os.Chmod(tempFile.Name(), 0666)

	return nil
}
