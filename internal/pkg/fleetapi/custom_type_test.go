// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTimeSerialized(t *testing.T) {
	then := time.Date(
		2020, 1, 8, 6, 30, 00, 651387237, time.UTC)

	b, err := json.Marshal(Time(then))
	require.NoError(t, err)

	require.Equal(t, "\"2020-01-08T06:30:00.651387237Z\"", string(b))
}
