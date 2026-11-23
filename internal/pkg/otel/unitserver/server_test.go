// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package unitserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
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
	socket := filepath.Join(t.TempDir(), "units.sock")
	address := "unix://" + socket
	s, err := New(log, address, &info.AgentInfo{}, 100*1024*1024)
	require.NoError(t, err)
	require.NoError(t, s.Start(ctx))

	// The server listens as soon as Start returns, so a receiver started after
	// it never finds the socket missing.
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", socket)
	require.NoError(t, err, "the server should be listening when Start returns")
	require.NoError(t, conn.Close())

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

	assert.Eventually(t, func() bool {
		s.mx.Lock()
		defer s.mx.Unlock()
		return !s.components["synthetics-default"].lastCheckin.IsZero()
	}, 10*time.Second, 10*time.Millisecond, "the receiver's check-in should be recorded")

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
	require.Eventually(t, func() bool {
		_, err := os.Stat(socket)
		return errors.Is(err, os.ErrNotExist)
	}, 10*time.Second, 10*time.Millisecond, "the socket should be removed once the server stops")
}

// Start returns errors in setting the server up, rather than reporting them
// later, so the caller knows the server isn't running.
func TestServerStartError(t *testing.T) {
	log, _ := loggertest.New("unitserver")
	// A socket under a regular file can't be created.
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	s, err := New(log, "unix://"+filepath.Join(file, "units.sock"), &info.AgentInfo{}, 1024)
	require.NoError(t, err)
	assert.Error(t, s.Start(t.Context()))
}

// Missed check-ins count from the last check-in, or from when the component
// was added if its receiver never checked in.
func TestMissedCheckins(t *testing.T) {
	log, _ := loggertest.New("unitserver")
	s, err := New(log, "unix://"+filepath.Join(t.TempDir(), "units.sock"), &info.AgentInfo{}, 1024)
	require.NoError(t, err)
	const period = 50 * time.Millisecond

	_, ok := s.MissedCheckins("synthetics-default", period)
	assert.False(t, ok, "an unknown component has no check-ins")

	s.Update([]component.Component{controlProtocolComponent("synthetics-default", "@every 1m")})
	missed, ok := s.MissedCheckins("synthetics-default", period)
	require.True(t, ok)
	assert.Zero(t, missed, "a new component has missed no check-ins")

	assert.Eventually(t, func() bool {
		missed, _ := s.MissedCheckins("synthetics-default", period)
		return missed >= 2
	}, 10*time.Second, period/5, "a receiver that never checks in should miss check-ins")

	s.checkedIn("synthetics-default")
	missed, _ = s.MissedCheckins("synthetics-default", period)
	assert.Zero(t, missed, "a check-in should reset the missed check-ins")
}

// As for beat processes, a unit's config is only sent if the receiver doesn't
// have it yet, for example when it reconnects.
func TestCheckinV2OmitsAppliedConfigs(t *testing.T) {
	log, _ := loggertest.New("unitserver")
	s, err := New(log, "unix://"+filepath.Join(t.TempDir(), "units.sock"), &info.AgentInfo{}, 100*1024*1024)
	require.NoError(t, err)
	comp := controlProtocolComponent("synthetics-default", "@every 1m")
	s.Update([]component.Component{comp})

	// The receiver reconnects with all the configs it was sent before.
	s.mx.Lock()
	cu := s.components[comp.ID]
	reconnect := &proto.CheckinObserved{Token: cu.token}
	for _, unit := range cu.units {
		reconnect.Units = append(reconnect.Units, &proto.UnitObserved{Id: unit.Id, Type: unit.Type, ConfigStateIdx: unit.ConfigStateIdx})
	}
	s.mx.Unlock()

	stream := &fakeCheckinStream{
		ctx:      t.Context(),
		observed: make(chan *proto.CheckinObserved, 1),
		expected: make(chan *proto.CheckinExpected, 10),
	}
	stream.observed <- reconnect
	done := make(chan error, 1)
	go func() { done <- s.CheckinV2(stream) }()

	// configs returns the config of each unit in the next message, nil if omitted.
	configs := func() map[string]*proto.UnitExpectedConfig {
		select {
		case msg := <-stream.expected:
			configs := make(map[string]*proto.UnitExpectedConfig)
			for _, unit := range msg.Units {
				configs[unit.Id] = unit.Config
			}
			return configs
		case <-time.After(10 * time.Second):
			require.FailNow(t, "timed out waiting for expected units")
			return nil
		}
	}

	assert.Equal(t, map[string]*proto.UnitExpectedConfig{"monitor-a": nil, "output": nil}, configs(),
		"the receiver should be sent its units without the configs it has")

	s.Update([]component.Component{controlProtocolComponent("synthetics-default", "@every 5m")})
	changed := configs()
	require.Len(t, changed, 2, "every expected unit should still be sent")
	assert.Nil(t, changed["output"], "the receiver already has the output config")
	require.NotNil(t, changed["monitor-a"], "the changed config should be sent")
	assert.Equal(t, "@every 5m", changed["monitor-a"].Source.AsMap()["schedule"])

	close(stream.observed)
	require.Error(t, <-done)
}

// fakeCheckinStream is a check-in stream that records the expected state sent to
// the receiver.
type fakeCheckinStream struct {
	grpc.ServerStream
	ctx      context.Context
	observed chan *proto.CheckinObserved
	expected chan *proto.CheckinExpected
}

func (f *fakeCheckinStream) Context() context.Context { return f.ctx }

func (f *fakeCheckinStream) Send(msg *proto.CheckinExpected) error {
	f.expected <- msg
	return nil
}

func (f *fakeCheckinStream) Recv() (*proto.CheckinObserved, error) {
	msg, ok := <-f.observed
	if !ok {
		return nil, io.EOF
	}
	return msg, nil
}

// A unit that is removed and added again gets a new config state index, so a
// receiver that missed the removal still applies its new config.
func TestConfigStateIdxNeverRepeats(t *testing.T) {
	unit := func(schedule string) component.Unit {
		return controlProtocolComponent("synthetics-default", schedule).Units[0]
	}
	key := unitKey{unitType: client.UnitTypeInput, id: "monitor-a"}
	cu := &componentUnits{units: make(map[unitKey]*proto.UnitExpected)}

	require.True(t, cu.update([]component.Unit{unit("@every 1m")}))
	first := cu.units[key].ConfigStateIdx

	require.True(t, cu.update([]component.Unit{unit("@every 2m")}))
	changed := cu.units[key].ConfigStateIdx
	assert.Greater(t, changed, first, "a config change should increase the index")

	require.False(t, cu.update([]component.Unit{unit("@every 2m")}), "an unchanged config should not change the units")
	assert.Equal(t, changed, cu.units[key].ConfigStateIdx)

	require.True(t, cu.update(nil))
	require.True(t, cu.update([]component.Unit{unit("@every 3m")}))
	assert.Greater(t, cu.units[key].ConfigStateIdx, changed, "a re-added unit should get a new index")
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
