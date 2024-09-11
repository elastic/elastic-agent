// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package details

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDetailsNew(t *testing.T) {
	det := NewDetails("99.999.9999", StateRequested, "test_action_id")
	require.Equal(t, StateRequested, det.State)
	require.Equal(t, "99.999.9999", det.TargetVersion)
	require.Equal(t, "test_action_id", det.ActionID)
	require.Equal(t, Metadata{}, det.Metadata)
}

func TestDetailsSetState(t *testing.T) {
	det := NewDetails("99.999.9999", StateRequested, "test_action_id")
	require.Equal(t, StateRequested, det.State)

	det.SetState(StateDownloading)
	require.Equal(t, StateDownloading, det.State)
}

func TestDetailsFail(t *testing.T) {
	det := NewDetails("99.999.9999", StateRequested, "test_action_id")
	require.Equal(t, StateRequested, det.State)

	err := errors.New("test error")
	det.Fail(err)
	require.Equal(t, StateFailed, det.State)
	require.Equal(t, StateRequested, det.Metadata.FailedState)
	require.Equal(t, err.Error(), det.Metadata.ErrorMsg)

	// Check that resetting state to something other than StateFailed
	// clears Metadata.FailedState and Metadata.ErrorMsg
	det.SetState(StateDownloading)
	require.Equal(t, State(""), det.Metadata.FailedState)
	require.Equal(t, "", det.Metadata.ErrorMsg)
}

func TestDetailsObserver(t *testing.T) {
	det := NewDetails("99.999.9999", StateRequested, "test_action_id")
	require.Equal(t, StateRequested, det.State)

	var observedDetails *Details
	obs := func(updatedDetails *Details) { observedDetails = updatedDetails }

	det.RegisterObserver(obs)
	require.Len(t, det.observers, 1)
	require.NotNil(t, observedDetails)
	require.Equal(t, StateRequested, observedDetails.State)

	det.SetState(StateDownloading)
	require.Equal(t, StateDownloading, det.State)
	require.Equal(t, StateDownloading, observedDetails.State)

	det.SetState(StateCompleted)
	require.Equal(t, StateCompleted, det.State)
	require.Nil(t, nil, observedDetails)
}

func TestDetailsDownloadRateJSON(t *testing.T) {
	det := NewDetails("99.999.9999", StateRequested, "test_action_id")

	tests := []struct {
		name     string
		percent  float64
		rate_in  float64
		rate_out float64
	}{
		{"non_infinity", .8, 1794.7, 1794.7},
		{"positive_infinity", 0.99, math.Inf(1), 0},
		{"negative_infinity", 0.99, math.Inf(-1), 0},
		{"not_a_number", 0.99, math.NaN(), 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			det.SetDownloadProgress(tc.percent, tc.rate_in)

			data, err := json.Marshal(det)
			require.NoError(t, err)

			var unmarshalledDetails Details
			err = json.Unmarshal(data, &unmarshalledDetails)
			require.NoError(t, err)
			require.Equal(t, tc.rate_out, float64(unmarshalledDetails.Metadata.DownloadRate))
			require.Equal(t, tc.percent, unmarshalledDetails.Metadata.DownloadPercent)
		})
	}
}

func TestEquals(t *testing.T) {
	details1 := NewDetails("8.12.0", StateDownloading, "foobar")
	details1.SetDownloadProgress(0.1234, 34.56)
	details1.SetRetryableError(errors.New("retryable error"))
	retryUntil1 := time.Date(2023, 11, 29, 11, 00, 32, 0, time.UTC)
	details1.SetRetryUntil(&retryUntil1)
	details1.Fail(errors.New("download failed"))

	details2 := NewDetails("8.12.0", StateDownloading, "foobar")
	details2.SetDownloadProgress(0.1234, 34.56)
	details2.SetRetryableError(errors.New("retryable error"))
	retryUntil2 := time.Date(2023, 11, 29, 11, 00, 32, 0, time.UTC)
	details2.SetRetryUntil(&retryUntil2)
	details2.Fail(errors.New("download failed"))

	details3 := NewDetails("8.12.0", StateDownloading, "foobar")

	require.True(t, details1.Equals(details2))
	require.False(t, details1.Equals(details3))

	// Nil checks
	var details4 *Details
	var details5 *Details

	require.True(t, details4.Equals(details5))
	require.False(t, details1.Equals(details4))
	require.False(t, details4.Equals(details1))
}
