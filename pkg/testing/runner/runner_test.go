// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestNewRunner_Clean(t *testing.T) {
	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "state")
	err := os.MkdirAll(stateDir, 0755)
	require.NoError(t, err)

	cfg := Config{
		AgentVersion: "8.10.0",
		StackVersion: "8.10.0-SNAPSHOT",
		BuildDir:     filepath.Join(tmpdir, "build"),
		GOVersion:    "1.20.7",
		RepoDir:      filepath.Join(tmpdir, "repo"),
		StateDir:     stateDir,
		ExtraEnv:     nil,
	}
	ip := &fakeInstanceProvisioner{}
	sp := &fakeStackProvisioner{}
	r, err := NewRunner(cfg, ip, sp)
	require.NoError(t, err)

	i1 := Instance{
		ID:          "id-1",
		Name:        "name-1",
		Provisioner: ip.Name(),
		IP:          "127.0.0.1",
		Username:    "ubuntu",
		RemotePath:  "/home/ubuntu/agent",
		Internal:    map[string]interface{}{}, // ElementsMatch fails without this set
	}
	err = r.addOrUpdateInstance(StateInstance{
		Instance: i1,
		Prepared: true,
	})
	require.NoError(t, err)
	i2 := Instance{
		ID:          "id-2",
		Name:        "name-2",
		Provisioner: ip.Name(),
		IP:          "127.0.0.2",
		Username:    "ubuntu",
		RemotePath:  "/home/ubuntu/agent",
		Internal:    map[string]interface{}{}, // ElementsMatch fails without this set
	}
	err = r.addOrUpdateInstance(StateInstance{
		Instance: i2,
		Prepared: true,
	})
	require.NoError(t, err)
	s1 := Stack{
		ID:          "id-1",
		Provisioner: sp.Name(),
		Version:     "8.10.0",
		Internal:    map[string]interface{}{}, // ElementsMatch fails without this set
	}
	err = r.addOrUpdateStack(s1)
	require.NoError(t, err)
	s2 := Stack{
		ID:          "id-2",
		Provisioner: sp.Name(),
		Version:     "8.9.0",
		Internal:    map[string]interface{}{}, // ElementsMatch fails without this set
	}
	err = r.addOrUpdateStack(s2)
	require.NoError(t, err)

	// create the runner again ensuring that it loads the saved state
	r, err = NewRunner(cfg, ip, sp)
	require.NoError(t, err)

	// clean should use the stored state
	err = r.Clean()
	require.NoError(t, err)

	assert.ElementsMatch(t, ip.instances, []Instance{i1, i2})
	assert.ElementsMatch(t, sp.deletedStacks, []Stack{s1, s2})
}

type fakeInstanceProvisioner struct {
	batches   []OSBatch
	instances []Instance
}

func (p *fakeInstanceProvisioner) Name() string {
	return "fake"
}

func (p *fakeInstanceProvisioner) SetLogger(_ Logger) {
}

func (p *fakeInstanceProvisioner) Supported(_ define.OS) bool {
	return true
}

func (p *fakeInstanceProvisioner) Provision(_ context.Context, _ Config, batches []OSBatch) ([]Instance, error) {
	p.batches = batches
	var instances []Instance
	for _, batch := range batches {
		instances = append(instances, Instance{
			ID:         batch.ID,
			Name:       batch.ID,
			IP:         "127.0.0.1",
			Username:   "ubuntu",
			RemotePath: "/home/ubuntu/agent",
			Internal:   nil,
		})
	}
	return instances, nil
}

func (p *fakeInstanceProvisioner) Clean(_ context.Context, _ Config, instances []Instance) error {
	p.instances = instances
	return nil
}

type fakeStackProvisioner struct {
	mx            sync.Mutex
	requests      []StackRequest
	deletedStacks []Stack
}

func (p *fakeStackProvisioner) Name() string {
	return "fake"
}

func (p *fakeStackProvisioner) SetLogger(_ Logger) {
}

func (p *fakeStackProvisioner) Create(_ context.Context, request StackRequest) (Stack, error) {
	p.mx.Lock()
	defer p.mx.Unlock()
	p.requests = append(p.requests, request)
	return Stack{
		ID:            request.ID,
		Version:       request.Version,
		Elasticsearch: "http://localhost:9200",
		Kibana:        "http://localhost:5601",
		Username:      "elastic",
		Password:      "changeme",
		Internal:      nil,
		Ready:         false,
	}, nil
}

func (p *fakeStackProvisioner) WaitForReady(_ context.Context, stack Stack) (Stack, error) {
	stack.Ready = true
	return stack, nil
}

func (p *fakeStackProvisioner) Delete(_ context.Context, stack Stack) error {
	p.mx.Lock()
	defer p.mx.Unlock()
	p.deletedStacks = append(p.deletedStacks, stack)
	return nil
}
