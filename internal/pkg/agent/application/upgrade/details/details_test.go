// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package details

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetailsNew(t *testing.T) {
	det := NewDetails("99.999.9999", StateRequested, "test_action_id", DetailsMetadata{})
	require.Equal(t, StateRequested, det.State)
	require.Equal(t, "99.999.9999", det.TargetVersion)
	require.Equal(t, "test_action_id", det.ActionID)
	require.Equal(t, DetailsMetadata{}, det.Metadata)
}

func TestDetailsSetState(t *testing.T) {
	det := NewDetails("99.999.9999", StateRequested, "test_action_id", DetailsMetadata{})
	require.Equal(t, StateRequested, det.State)

	det.SetState(StateDownloading)
	require.Equal(t, StateDownloading, det.State)
}

func TestDetailsFail(t *testing.T) {
	det := NewDetails("99.999.9999", StateRequested, "test_action_id", DetailsMetadata{})
	require.Equal(t, StateRequested, det.State)

	err := errors.New("test error")
	det.Fail(err)
	require.Equal(t, StateFailed, det.State)
	require.Equal(t, StateRequested, det.Metadata.FailedState)
	require.Equal(t, err.Error(), det.Metadata.ErrorMsg)
}

func TestDetailsObserver(t *testing.T) {
	det := NewDetails("99.999.9999", StateRequested, "test_action_id", DetailsMetadata{})
	require.Equal(t, StateRequested, det.State)

	var observedDetails *Details
	obs := func(updatedDetails *Details) { observedDetails = updatedDetails }
	det.RegisterObserver(obs)
	require.Nil(t, observedDetails)
	require.Len(t, det.observers, 1)

	det.SetState(StateDownloading)
	require.Equal(t, StateDownloading, det.State)
	require.Equal(t, StateDownloading, observedDetails.State)

	det.SetState(StateCompleted)
	require.Equal(t, StateCompleted, det.State)
	require.Nil(t, nil, observedDetails)
}
