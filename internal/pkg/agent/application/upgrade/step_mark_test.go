// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestMarkUpgrade(t *testing.T) {
	log, _ := loggertest.New("test")
	agent := agentInstall{
		version:       "8.5.0",
		hash:          "abc123",
		versionedHome: "home/v8.5.0",
	}
	previousAgent := agentInstall{
		version:       "8.4.0",
		hash:          "xyz789",
		versionedHome: "home/v8.4.0",
	}
	action := &fleetapi.ActionUpgrade{
		ActionID:   "action-123",
		ActionType: "UPGRADE",
		Data: fleetapi.ActionUpgradeData{
			Version:   "8.5.0",
			SourceURI: "https://example.com/upgrade",
		},
	}
	upgradeDetails := details.NewDetails("8.5.0", details.StateScheduled, "action-123")

	testError := errors.New("test error")

	type testCase struct {
		fileName      string
		expectedError error
		markUpgrade   markUpgradeFunc
	}

	testCases := map[string]testCase{
		"should return error if it fails updating the active commit file": {
			fileName:      "commit",
			expectedError: testError,
			markUpgrade: markUpgradeProvider(func(log *logger.Logger, topDirPath, hash string, writeFile writeFileFunc) error {
				return testError
			}, func(name string, data []byte, perm os.FileMode) error {
				return nil
			}),
		},
		"should return error if it fails writing to marker file": {
			fileName:      "marker",
			expectedError: testError,
			markUpgrade: markUpgradeProvider(func(log *logger.Logger, topDirPath, hash string, writeFile writeFileFunc) error {
				return nil
			}, func(name string, data []byte, perm os.FileMode) error {
				return testError
			}),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			baseDir := t.TempDir()
			paths.SetTop(baseDir)

			err := tc.markUpgrade(log, paths.Data(), agent, previousAgent, action, upgradeDetails)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.expectedError)
		})
	}
}

func TestUpdateActiveCommit(t *testing.T) {
	log, _ := loggertest.New("test")
	testError := errors.New("test error")
	testCases := map[string]struct {
		expectedError error
		writeFileFunc writeFileFunc
	}{
		"should return error if it fails writing to file": {
			expectedError: testError,
			writeFileFunc: func(name string, data []byte, perm os.FileMode) error {
				return testError
			},
		},
		"should not return error if it writes to file": {
			expectedError: nil,
			writeFileFunc: func(name string, data []byte, perm os.FileMode) error {
				return nil
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			err := UpdateActiveCommit(log, paths.Top(), "hash", tc.writeFileFunc)
			require.ErrorIs(t, err, tc.expectedError)
		})
	}

}
