// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package downloads

import (
	"context"
	"log/slog"
	"os"
)

// exists checks if a path exists in the file system
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// mkdirAll creates all directories for a directory path
func mkdirAll(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.MkdirAll(path, 0755)
		if err != nil {
			logger.Log(context.Background(),
				FatalLevel,
				"Directory cannot be created",
				slog.String("error", err.Error()),
				slog.String("path", path),
			)

			return err
		}
	}

	return nil
}
