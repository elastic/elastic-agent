package upgrade

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestFSM(t *testing.T) {
	l, obs := logger.NewTesting("upgrade_fsm")
	cb := func(oldState, newState, action string) {
		// TODO
	}

	fsm := NewFSM(l, cb)

	// Test that valid transition succeeds
	err := fsm.Transition(context.Background(), ActionSucceeded)
	require.NoError(t, err)
	require.Equal(t, StateDownloading, fsm.Current())
	require.Equal(t, 1, obs.Len())

	log := obs.TakeAll()[0]
	require.Equal(t, "transitioning upgrade state machine", log.Message)
	require.Equal(t, "from", log.Context[0].Key)
	require.Equal(t, StateRequested, log.Context[0].String)
	require.Equal(t, "to", log.Context[1].Key)
	require.Equal(t, StateDownloading, log.Context[1].String)

	// Test that invalid transition returns error
	err = fsm.Transition(context.Background(), ActionRollingBack)
	require.Error(t, err)
	require.EqualError(t, err, fmt.Sprintf(
		"unable to transition from [%[1]s] with action [%[2]s]: event %[2]s inappropriate in current state %[1]s",
		StateDownloading, ActionRollingBack,
	))
	require.Equal(t, 0, obs.Len())
}
