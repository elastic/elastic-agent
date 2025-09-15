// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/pkg/utils"
)

func TestGetOwnerFromPathWindows(t *testing.T) {

	ownerSID, err := windows.StringToSid(utils.AdministratorSID)
	require.NoError(t, err)
	groupSID, err := windows.StringToSid(utils.AdministratorSID)
	require.NoError(t, err)

	testError := errors.New("test error")

	mockGetNamedSecurityInfoFactory := func(err error) getNamedSecurityInfo {
		return func(objectName string, objectType int32, secInfo uint32, owner, group **windows.SID, dacl, sacl, secDesc *windows.Handle) error {
			*owner = ownerSID
			*group = groupSID
			return err
		}
	}
	mockLocalFree := func(handle windows.Handle) (windows.Handle, error) {
		return windows.Handle(0), nil
	}

	type testCase struct {
		mockGetNamedSecurityInfo getNamedSecurityInfo
		mockLocalFree            localFree
		wantOwner                utils.FileOwner
		wantErr                  bool
	}

	testCases := map[string]testCase{
		"returns owner when getNamedSecurityInfo succeeds": {
			mockGetNamedSecurityInfo: mockGetNamedSecurityInfoFactory(nil),
			mockLocalFree:            mockLocalFree,
			wantOwner:                utils.FileOwner{UID: utils.AdministratorSID, GID: utils.AdministratorSID},
			wantErr:                  false,
		},
		"returns error when getNamedSecurityInfo fails": {
			mockGetNamedSecurityInfo: mockGetNamedSecurityInfoFactory(testError),
			mockLocalFree:            mockLocalFree,
			wantOwner:                utils.FileOwner{},
			wantErr:                  true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			owner, err := getOwnerFromPathWindows("test", tc.mockGetNamedSecurityInfo, tc.mockLocalFree)
			require.Equal(t, tc.wantOwner, owner)

			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}
