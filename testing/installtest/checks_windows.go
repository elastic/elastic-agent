// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package installtest

import (
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

func checkPlatform(f *atesting.Fixture, topPath string, unprivileged bool) error {
	if unprivileged {
		// Check that the elastic-agent user/group exist.
		_, err := install.FindUID(install.ElasticUsername)
		if err != nil {
			return fmt.Errorf("failed to find %s user: %w", install.ElasticUsername, err)
		}
		_, err = install.FindGID(install.ElasticGroupName)
		if err != nil {
			return fmt.Errorf("failed to find %s group: %w", install.ElasticGroupName, err)
		}
	}
	return nil
}
