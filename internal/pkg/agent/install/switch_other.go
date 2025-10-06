// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !darwin

package install

import (
	"github.com/elastic/elastic-agent/pkg/utils"
)

func switchPlatformMode(_ ProgressDescriber, _ utils.FileOwner) error {
	return nil
}
