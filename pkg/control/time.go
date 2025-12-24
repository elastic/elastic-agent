// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package control

import "time"

// TimeFormat returns the time format shared between the protocol.
func TimeFormat() string {
	return time.RFC3339Nano
}

// OldTimeFormat returns the old time format shared between the protocol.
func OldTimeFormat() string {
	return "2006-01-02 15:04:05 -0700 MST"
}
