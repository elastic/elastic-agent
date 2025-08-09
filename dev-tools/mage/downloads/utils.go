// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package downloads

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/cenkalti/backoff/v4"
)

// downloadRequest struct contains download details ad path and URL
type downloadRequest struct {
	URL        string
	TargetPath string
}

// downloadFile will download a url and store it in a temporary path.
// It writes to the destination file as it downloads it, without
// loading the entire file into memory.
func downloadFile(downloadRequest *downloadRequest) error {
	targetFile, err := os.Create(downloadRequest.TargetPath)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer func() {
		_ = targetFile.Close()
	}()

	exp := getExponentialBackoff(3)

	retryCount := 1
	var fileReader io.ReadCloser
	download := func() error {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, downloadRequest.URL, nil)
		if err != nil {
			return fmt.Errorf("creating request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // we do close this outside of the function
		if err != nil {
			retryCount++
			return fmt.Errorf("downloading file %s: %w", downloadRequest.URL, err)
		}

		fileReader = resp.Body
		return nil
	}

	err = backoff.Retry(download, exp)
	if err != nil {
		return err
	}

	_, err = io.Copy(targetFile, fileReader)
	if err != nil {
		return fmt.Errorf("writing file %s: %w", targetFile.Name(), err)
	}
	err = fileReader.Close()
	if err != nil {
		return fmt.Errorf("closing reader: %w", err)
	}

	_ = os.Chmod(targetFile.Name(), 0666)

	return nil
}
