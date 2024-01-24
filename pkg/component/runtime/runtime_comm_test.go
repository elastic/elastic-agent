// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/core/authority"
)

func TestRuntimeComm_WriteConnInfo_packageVersion(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), true)
	require.NoError(t, err, "could not create agent info")

	want := client.AgentInfo{
		ID:       agentInfo.AgentID(),
		Version:  agentInfo.Version(),
		Snapshot: agentInfo.Snapshot(),
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
	err = c.WriteConnInfo(&buff)
	require.NoError(t, err, "failed to write ConnInfo")

	clientv2, _, err := client.NewV2FromReader(&buff, client.VersionInfo{
		Name: "TestRuntimeComm_WriteConnInfo",
		Meta: nil,
	})
	require.NoError(t, err, "failed creating V2 client")

	assert.Equal(t, &want, clientv2.AgentInfo(),
		"package version does not match")
}
