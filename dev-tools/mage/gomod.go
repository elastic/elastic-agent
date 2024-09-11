// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent/dev-tools/mage/gotool"
)

// CopyModule contains a module name and the list of files or directories
// to copy recursively.
type CopyModule struct {
	Name        string
	FilesToCopy []string
}

// CopyFilesToVendor copies packages which require the whole tree
func CopyFilesToVendor(vendorFolder string, modulesToCopy []CopyModule) error {
	for _, p := range modulesToCopy {
		path, err := gotool.ListModuleCacheDir(p.Name)
		if err != nil {
			return fmt.Errorf("error while looking up cached dir of module: %s: %w", p.Name, err)
		}

		for _, f := range p.FilesToCopy {
			from := filepath.Join(path, f)
			to := filepath.Join(vendorFolder, p.Name, f)
			copyTask := &CopyTask{Source: from, Dest: to, Mode: 0600, DirMode: os.ModeDir | 0750}
			err = copyTask.Execute()
			if err != nil {
				return fmt.Errorf("error while copying file from %s to %s: %w", from, to, err)
			}
		}
	}
	return nil
}
