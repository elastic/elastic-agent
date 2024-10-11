// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/core/authority"
)

type agentInfoMock struct {
	agentID      string
	snapshot     bool
	version      string
	unprivileged bool
	isStandalone bool
}

func (a agentInfoMock) AgentID() string {
	return a.agentID
}
func (a agentInfoMock) Snapshot() bool {
	return a.snapshot
}

func (a agentInfoMock) Version() string {
	return a.version
}

func (a agentInfoMock) Unprivileged() bool {
	return a.unprivileged
}

func (a agentInfoMock) IsStandalone() bool {
	return a.isStandalone
}

func (a agentInfoMock) Headers() map[string]string                          { panic("implement me") }
func (a agentInfoMock) LogLevel() string                                    { panic("implement me") }
func (a agentInfoMock) RawLogLevel() string                                 { panic("implement me") }
func (a agentInfoMock) ReloadID(ctx context.Context) error                  { panic("implement me") }
func (a agentInfoMock) SetLogLevel(ctx context.Context, level string) error { panic("implement me") }

func TestCheckinExpected(t *testing.T) {
	ca, err := authority.NewCA()
	require.NoError(t, err, "could not create CA")
	pair, err := ca.GeneratePair()
	require.NoError(t, err, "could not create certificate pair from CA")
	test := runtimeComm{
		listenAddr: "localhost",
		ca:         ca,
		name:       "a_name",
		token:      "a_token",
		cert:       pair,
		agentInfo: agentInfoMock{
			agentID:      "testagent",
			snapshot:     true,
			version:      "8.13.0+build1966-09-6",
			unprivileged: true,
		},
		checkinExpected:       make(chan *proto.CheckinExpected, 1),
		checkinObserved:       make(chan *proto.CheckinObserved),
		initCheckinObservedMx: sync.Mutex{},
	}

	expected := &proto.CheckinExpected{}
	observed := &proto.CheckinObserved{}
	test.CheckinExpected(expected, observed)

	got := <-test.checkinExpected
	require.True(t, got.AgentInfo.Unprivileged)
	t.Logf("got : %#v", got)

}

func TestRuntimeComm_WriteStartUpInfo_packageVersion(t *testing.T) {
	agentInfo := agentInfoMock{
		agentID:      "NCC-1701",
		snapshot:     true,
		version:      "8.13.0+build1966-09-6",
		unprivileged: true,
	}

	want := client.AgentInfo{
		ID:           agentInfo.AgentID(),
		Version:      agentInfo.Version(),
		Snapshot:     agentInfo.Snapshot(),
		Unprivileged: agentInfo.Unprivileged(),
	}

	ca, err := authority.NewCA()
	require.NoError(t, err, "could not create CA")
	pair, err := ca.GeneratePair()
	require.NoError(t, err, "could not create certificate pair from CA")

	c := runtimeComm{
		listenAddr: "localhost",
		ca:         ca,
		name:       "a_name",
		token:      "a_token",
		cert:       pair,
		agentInfo:  agentInfo,
	}

	buff := bytes.Buffer{}
	err = c.WriteStartUpInfo(&buff)
	require.NoError(t, err, "failed to write ConnInfo")

	clientv2, _, err := client.NewV2FromReader(&buff, client.VersionInfo{
		Name: "TestRuntimeComm_WriteConnInfo",
		Meta: nil,
	})
	require.NoError(t, err, "failed creating V2 client")

	assert.Equal(t, &want, clientv2.AgentInfo(),
		"agent info returned by client must match what has been written on command input")
}
