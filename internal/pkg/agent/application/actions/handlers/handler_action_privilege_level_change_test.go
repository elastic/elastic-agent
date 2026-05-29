// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"os/user"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestIsTargetingSameUser(t *testing.T) {
	tests := []struct {
		name        string
		currentUID  string
		currentGID  string
		targetUID   string
		targetGID   string
		expectEqual bool
	}{
		{
			name:        "same user and group",
			currentUID:  "1000",
			currentGID:  "1000",
			targetUID:   "1000",
			targetGID:   "1000",
			expectEqual: true,
		},
		{
			name:        "different user same group",
			currentUID:  "1000",
			currentGID:  "1000",
			targetUID:   "1001",
			targetGID:   "1000",
			expectEqual: false,
		},
		{
			name:        "same user different group",
			currentUID:  "1000",
			currentGID:  "1000",
			targetUID:   "1000",
			targetGID:   "1001",
			expectEqual: false,
		},
		{
			name:        "different user and different group",
			currentUID:  "1000",
			currentGID:  "1000",
			targetUID:   "1001",
			targetGID:   "1001",
			expectEqual: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := targetingSameUser(tt.currentUID, tt.currentGID, tt.targetUID, tt.targetGID)
			if result != tt.expectEqual {
				t.Errorf("expected targetingSameUser to be %v, got %v", tt.expectEqual, result)
			}
		})
	}
}

func TestAckerIsInvokedForSameUser(t *testing.T) {
	log, _ := logger.New("", false)
	h := &PrivilegeLevelChange{
		log: log,
	}

	acker := &mockAcker{}

	currentUser, err := user.Current()
	require.NoError(t, err)

	group, err := user.LookupGroupId(currentUser.Gid)
	require.NoError(t, err)

	action := &fleetapi.ActionPrivilegeLevelChange{
		ActionID:   "id",
		ActionType: "PRIVILEGE_LEVEL_CHANGE",
		Data: fleetapi.ActionPrivilegeLevelChangeData{
			Unprivileged: true,
			UserInfo: &fleetapi.UserInfo{
				Username:  currentUser.Username,
				Groupname: group.Name,
			},
		},
	}

	acker.On("Ack", mock.Anything, action).Return(nil)
	acker.On("Commit", mock.Anything).Return(nil)

	ctx := context.Background()

	err = h.handleChange(ctx, action, acker, action, false)
	require.NoError(t, err)
	acker.IsMethodCallable(t, "Ack")
	acker.IsMethodCallable(t, "Commit")
}

type mockAcker struct {
	mock.Mock
}

func (m *mockAcker) Ack(ctx context.Context, a fleetapi.Action) error {
	args := m.Called(ctx, a)
	return args.Error(0)
}
func (m *mockAcker) Commit(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
