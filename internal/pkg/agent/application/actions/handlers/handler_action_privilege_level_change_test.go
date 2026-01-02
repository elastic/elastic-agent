// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import "testing"

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
			expectEqual: false,
		},
		{
			name:        "different user same group",
			currentUID:  "1000",
			currentGID:  "1000",
			targetUID:   "1001",
			targetGID:   "1000",
			expectEqual: true,
		},
		{
			name:        "same user different group",
			currentUID:  "1000",
			currentGID:  "1000",
			targetUID:   "1000",
			targetGID:   "1001",
			expectEqual: true,
		},
		{
			name:        "different user and different group",
			currentUID:  "1000",
			currentGID:  "1000",
			targetUID:   "1001",
			targetGID:   "1001",
			expectEqual: true,
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
