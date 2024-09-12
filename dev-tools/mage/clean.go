// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"github.com/magefile/mage/sh"
)

// DefaultCleanPaths specifies a list of files or paths to recursively delete.
// The values may contain variables and will be expanded at the time of use.
var DefaultCleanPaths = []string{
	"build",
	"docker-compose.yml.lock",
	"{{.BeatName}}",
	"{{.BeatName}}.exe",
	"{{.BeatName}}.test",
	"{{.BeatName}}.test.exe",
	"fields.yml",
	"_meta/fields.generated.yml",
	"_meta/kibana.generated",
	"_meta/kibana/6/index-pattern/{{.BeatName}}.json",
	"_meta/kibana/7/index-pattern/{{.BeatName}}.json",
}

// Clean clean generated build artifacts.
func Clean(pathLists ...[]string) error {
	if len(pathLists) == 0 {
		pathLists = [][]string{DefaultCleanPaths}
	}
	for _, paths := range pathLists {
		for _, f := range paths {
			f = MustExpand(f)
			if err := sh.Rm(f); err != nil {
				return err
			}
		}
	}
	return nil
}
