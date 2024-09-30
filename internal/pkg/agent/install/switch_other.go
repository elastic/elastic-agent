// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !darwin

package install

import (
	"github.com/schollz/progressbar/v3"

	"github.com/elastic/elastic-agent/pkg/utils"
)

func switchPlatformMode(pt *progressbar.ProgressBar, ownership utils.FileOwner) error {
	return nil
}
