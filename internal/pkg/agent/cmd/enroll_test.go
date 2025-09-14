// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func TestComputeFixPermissions(t *testing.T) {

	type testCase struct {
		fromInstall               bool
		hasRoot                   bool
		goos                      string
		ownerFromCmdOwner         utils.FileOwner
		ownerFromCmdErr           error
		ownerFromPathOwner        utils.FileOwner
		ownerFromPathErr          error
		wantOwner                 *utils.FileOwner
		wantErr                   bool
		expectOwnerFromCmdCalled  bool
		expectOwnerFromPathCalled bool
	}

	owner := utils.FileOwner{}
	testError := errors.New("test error")

	testCases := map[string]testCase{
		"should use owner from flags when enrolling from installer on non-darwin": {
			fromInstall:               true,
			hasRoot:                   true,
			goos:                      "linux",
			ownerFromCmdOwner:         owner,
			wantOwner:                 &owner,
			expectOwnerFromCmdCalled:  true,
			expectOwnerFromPathCalled: false,
		},
		"should skip fixing permissions when enrolling from installer on darwin": {
			fromInstall:               true,
			hasRoot:                   true,
			goos:                      "darwin",
			wantOwner:                 nil,
			expectOwnerFromCmdCalled:  false,
			expectOwnerFromPathCalled: false,
		},
		"should return error when getting owner from cmd fails during installer enroll": {
			fromInstall:               true,
			hasRoot:                   true,
			goos:                      "linux",
			ownerFromCmdErr:           testError,
			wantErr:                   true,
			expectOwnerFromCmdCalled:  true,
			expectOwnerFromPathCalled: false,
		},
		"should use owner from binary path when not from installer with root on linux": {
			fromInstall:               false,
			hasRoot:                   true,
			goos:                      "linux",
			ownerFromPathOwner:        owner,
			wantOwner:                 &owner,
			expectOwnerFromCmdCalled:  false,
			expectOwnerFromPathCalled: true,
		},
		"should return owner from path when not from install and has root on windows": {
			fromInstall:               false,
			hasRoot:                   true,
			goos:                      "windows",
			ownerFromPathOwner:        owner,
			wantOwner:                 &owner,
			expectOwnerFromCmdCalled:  false,
			expectOwnerFromPathCalled: true,
		},
		"should skip fixing permissions when not from installer without root": {
			fromInstall:               false,
			hasRoot:                   false,
			goos:                      "linux",
			wantOwner:                 nil,
			expectOwnerFromCmdCalled:  false,
			expectOwnerFromPathCalled: false,
		},
		"should return error when getting owner from path fails": {
			fromInstall:               false,
			hasRoot:                   true,
			goos:                      "linux",
			ownerFromPathErr:          testError,
			wantErr:                   true,
			expectOwnerFromCmdCalled:  false,
			expectOwnerFromPathCalled: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var ownerFromCmdCalled, ownerFromPathCalled bool
			var receivedPath string

			mockOwnerFromCmdFunc := func(_ *cobra.Command) (utils.FileOwner, error) {
				ownerFromCmdCalled = true
				if tc.ownerFromCmdErr != nil {
					return utils.FileOwner{}, tc.ownerFromCmdErr
				}
				return tc.ownerFromCmdOwner, nil
			}
			mockOwnerFromPathFunc := func(p string) (utils.FileOwner, error) {
				ownerFromPathCalled = true
				receivedPath = p
				if tc.ownerFromPathErr != nil {
					return utils.FileOwner{}, tc.ownerFromPathErr
				}
				return tc.ownerFromPathOwner, nil
			}

			got, err := computeFixPermissions(tc.fromInstall, tc.hasRoot, tc.goos, mockOwnerFromCmdFunc, mockOwnerFromPathFunc, &cobra.Command{})

			if tc.wantErr {
				require.Error(t, err, "expected error")
				require.Nil(t, got, "expected nil owner for error")
				return
			}

			require.NoError(t, err, "expected no error")

			if tc.wantOwner == nil {
				require.Nil(t, got, "expected nil owner")
			} else {
				require.NotNil(t, got, "expected non-nil owner")
				require.Equal(t, tc.wantOwner, got, "owner mismatch")
			}

			require.Equal(t, tc.expectOwnerFromCmdCalled, ownerFromCmdCalled, "ownerFromCmdCalled mismatch")
			require.Equal(t, tc.expectOwnerFromPathCalled, ownerFromPathCalled, "ownerFromPathCalled mismatch")

			if tc.expectOwnerFromPathCalled {
				require.Equal(t, paths.Top(), receivedPath, "received path mismatch")
			}
		})
	}
}
