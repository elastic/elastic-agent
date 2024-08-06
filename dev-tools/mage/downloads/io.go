// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package downloads

import (
	"os"

	log "github.com/sirupsen/logrus"
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
			log.WithFields(log.Fields{
				"error": err,
				"path":  path,
			}).Fatal("Directory cannot be created")

			return err
		}
	}

	return nil
}
