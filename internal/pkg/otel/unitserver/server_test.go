// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package unitserver

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func controlProtocolComponent(id string, schedule string) component.Component {
	return component.Component{
		ID:             id,
		RuntimeManager: component.OtelRuntimeManager,
		InputSpec: &component.InputRuntimeSpec{
			Spec: component.InputSpec{SingleReceiver: true, ControlProtocolUnits: true},
		},
		Units: []component.Unit{
			{
				ID:     "monitor-a",
				Type:   client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{"type": "synthetics/tcp", "schedule": schedule}),
			},
			{
				ID:     "output",
				Type:   client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{"type": "elasticsearch"}),
			},
		},
	}
}

func TestServer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	log, _ := loggertest.New("unitserver")
	address := "unix://" + filepath.Join(t.TempDir(), "units.sock")
	s, err := New(log, address, &info.AgentInfo{}, 100*1024*1024)
	require.NoError(t, err)
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx) }()

	// Units of other components are never sent.
	otherComp := component.Component{ID: "filestream-default", RuntimeManager: component.OtelRuntimeManager}
	s.Update([]component.Component{controlProtocolComponent("synthetics-default", "@every 1m"), otherComp})
	_, err = s.ConnectionInfo(otherComp.ID)
	require.Error(t, err)

	// A client without the component's credentials gets nothing.
	assertRejected(t, address, "synthetics-default")

	// The receiver connects with the connection info, as a beat process does.
	connInfo, err := s.ConnectionInfo("synthetics-default")
	require.NoError(t, err)
	agentClient, _, err := client.NewV2FromReader(bytes.NewReader(connInfo), client.VersionInfo{Name: "test"})
	require.NoError(t, err)
	require.NoError(t, agentClient.Start(ctx))
	drainCtx, stopDrain := context.WithCancel(t.Context())
	changes := drain(drainCtx, t, agentClient)
	defer func() {
		// stop the client while its channels are still drained
		agentClient.Stop()
		stopDrain()
	}()

	units := map[string]*client.Unit{}
	for range 2 {
		change := waitForChange(t, changes)
		require.Equal(t, client.UnitChangedAdded, change.Type)
		units[change.Unit.ID()] = change.Unit
	}
	require.Contains(t, units, "monitor-a")
	require.Contains(t, units, "output")
	assert.Equal(t, "@every 1m", units["monitor-a"].Expected().Config.Source.AsMap()["schedule"])

	// Changing the input sends only that unit as modified.
	s.Update([]component.Component{controlProtocolComponent("synthetics-default", "@every 5m"), otherComp})
	change := waitForChange(t, changes)
	assert.Equal(t, client.UnitChangedModified, change.Type)
	assert.Equal(t, "monitor-a", change.Unit.ID())
	assert.Equal(t, "@every 5m", change.Unit.Expected().Config.Source.AsMap()["schedule"])

	// Removing the component removes its units.
	s.Update([]component.Component{otherComp})
	for range 2 {
		assert.Equal(t, client.UnitChangedRemoved, waitForChange(t, changes).Type)
	}

	cancel()
	err = <-runErr
	assert.True(t, err == nil || errors.Is(err, context.Canceled), "unexpected error: %v", err)
}

// assertRejected checks that a client connecting without TLS, using the
// component ID as the token, never receives units.
func assertRejected(t *testing.T, address string, token string) {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := proto.NewElasticAgentClient(conn).CheckinV2(ctx)
	if err == nil {
		if err = stream.Send(&proto.CheckinObserved{Token: token}); err == nil {
			_, err = stream.Recv()
		}
	}
	require.Error(t, err)
}

// drain reads the client channels, as the client blocks until they are read.
func drain(ctx context.Context, t *testing.T, agentClient client.V2) <-chan client.UnitChanged {
	changes := make(chan client.UnitChanged, 100)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case change := <-agentClient.UnitChanges():
				changes <- change
			case err := <-agentClient.Errors():
				t.Logf("client error: %v", err)
			}
		}
	}()
	return changes
}

func waitForChange(t *testing.T, changes <-chan client.UnitChanged) client.UnitChanged {
	select {
	case change := <-changes:
		return change
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for a unit change")
		return client.UnitChanged{}
	}
}
