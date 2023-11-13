// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package info

import (
	"github.com/elastic/elastic-agent/pkg/utils"
)

func fixInstallMarkerPermissions(markerFilePath string, ownership utils.FileOwner) error {
	// TODO(blakerouse): Fix the market permissions on Windows.
	return nil
}
