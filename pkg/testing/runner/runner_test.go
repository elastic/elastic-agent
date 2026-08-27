// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/dev-tools/mage"
	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestNewRunner_Clean(t *testing.T) {
	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "state")
	err := os.MkdirAll(stateDir, 0755)
	require.NoError(t, err)
	settings, err := mage.LoadSettings()
	require.NoError(t, err)

	goVersion := settings.GoVersion()

	cfg := common.Config{
		AgentVersion: "8.10.0",
		StackVersion: "8.10.0-SNAPSHOT",
		BuildDir:     filepath.Join(tmpdir, "build"),
		GOVersion:    goVersion,
		RepoDir:      filepath.Join(tmpdir, "repo"),
		StateDir:     stateDir,
		ExtraEnv:     nil,
	}
	ip := &fakeInstanceProvisioner{}
	sp := &fakeStackProvisioner{}
	r, err := NewRunner(cfg, ip, sp)
	require.NoError(t, err)

	i1 := common.Instance{
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
	i2 := common.Instance{
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
	s1 := common.Stack{
		ID:          "id-1",
		Provisioner: sp.Name(),
		Version:     "8.10.0",
		Internal:    map[string]interface{}{}, // ElementsMatch fails without this set
	}
	err = r.addOrUpdateStack(s1)
	require.NoError(t, err)
	s2 := common.Stack{
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

	assert.ElementsMatch(t, ip.instances, []common.Instance{i1, i2})
	assert.ElementsMatch(t, sp.deletedStacks, []common.Stack{s1, s2})
}

func TestRunnerCleanPreservesStateOnFailure(t *testing.T) {
	tmpdir := t.TempDir()
	stateDir := filepath.Join(tmpdir, "state")
	require.NoError(t, os.MkdirAll(stateDir, 0o755))
	settings, err := mage.LoadSettings()
	require.NoError(t, err)

	cfg := common.Config{
		AgentVersion: "9.6.0-SNAPSHOT",
		StackVersion: "9.6.0-SNAPSHOT",
		BuildDir:     filepath.Join(tmpdir, "build"),
		RepoDir:      filepath.Join(tmpdir, "repo"),
		StateDir:     stateDir,
		GOVersion:    settings.GoVersion(),
	}
	ip := &fakeInstanceProvisioner{cleanErr: errors.New("instance cleanup failed")}
	sp := &fakeStackProvisioner{}
	r, err := NewRunner(cfg, ip, sp)
	require.NoError(t, err)
	require.NoError(t, r.addOrUpdateInstance(StateInstance{Instance: common.Instance{Name: "instance", Provisioner: ip.Name()}}))
	require.NoError(t, r.addOrUpdateStack(common.Stack{ID: "stack", Provisioner: sp.Name()}))

	require.Error(t, r.Clean())

	reloaded, err := NewRunner(cfg, &fakeInstanceProvisioner{}, &fakeStackProvisioner{})
	require.NoError(t, err)
	require.Len(t, reloaded.state.Instances, 1)
	require.Len(t, reloaded.state.Stacks, 1)
}

func TestInternalString(t *testing.T) {
	internal := map[string]interface{}{
		"present": "https://127.0.0.1:9200",
		"empty":   "",
		"wrong":   9200,
	}
	assert.Equal(t, "https://127.0.0.1:9200", internalString(internal, "present", "fallback"))
	assert.Equal(t, "fallback", internalString(internal, "empty", "fallback"))
	assert.Equal(t, "fallback", internalString(internal, "wrong", "fallback"))
	assert.Equal(t, "fallback", internalString(nil, "missing", "fallback"))
}

func TestValidateProvisionerCompatibility(t *testing.T) {
	tests := []struct {
		name     string
		instance *fakeInstanceProvisioner
		stack    *fakeStackProvisioner
		wantErr  bool
	}{
		{
			name:     "remote stack accepts remote instance",
			instance: &fakeInstanceProvisioner{location: common.ProvisionerLocationRemote},
			stack:    &fakeStackProvisioner{location: common.ProvisionerLocationRemote},
		},
		{
			name:     "remote stack accepts local instance",
			instance: &fakeInstanceProvisioner{location: common.ProvisionerLocationLocal},
			stack:    &fakeStackProvisioner{location: common.ProvisionerLocationRemote},
		},
		{
			name:     "local stack rejects remote instance",
			instance: &fakeInstanceProvisioner{location: common.ProvisionerLocationRemote},
			stack:    &fakeStackProvisioner{location: common.ProvisionerLocationLocal},
			wantErr:  true,
		},
		{
			name:     "local stack rejects unsupported local instance",
			instance: &fakeInstanceProvisioner{location: common.ProvisionerLocationLocal},
			stack:    &fakeStackProvisioner{location: common.ProvisionerLocationLocal},
			wantErr:  true,
		},
		{
			name: "local stack accepts compatible local instance",
			instance: &fakeInstanceProvisioner{
				location:             common.ProvisionerLocationLocal,
				localStackCompatible: true,
			},
			stack: &fakeStackProvisioner{location: common.ProvisionerLocationLocal},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProvisionerCompatibility(tt.instance, tt.stack)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

type fakeInstanceProvisioner struct {
	batches              []common.OSBatch
	instances            []common.Instance
	cleanErr             error
	location             common.ProvisionerLocation
	localStackCompatible bool
}

func (p *fakeInstanceProvisioner) Name() string {
	return "fake"
}

func (p *fakeInstanceProvisioner) Type() common.ProvisionerType {
	return common.ProvisionerTypeVM
}

func (p *fakeInstanceProvisioner) Location() common.ProvisionerLocation { return p.location }

func (p *fakeInstanceProvisioner) SupportsLocalStack() bool { return p.localStackCompatible }

func (p *fakeInstanceProvisioner) SetLogger(_ common.Logger) {
}

func (p *fakeInstanceProvisioner) Supported(_ define.OS) bool {
	return true
}

func (p *fakeInstanceProvisioner) Provision(_ context.Context, _ common.Config, batches []common.OSBatch) ([]common.Instance, error) {
	p.batches = batches
	var instances []common.Instance
	for _, batch := range batches {
		instances = append(instances, common.Instance{
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

func (p *fakeInstanceProvisioner) Clean(_ context.Context, _ common.Config, instances []common.Instance) error {
	p.instances = instances
	return p.cleanErr
}

type fakeStackProvisioner struct {
	mx            sync.Mutex
	requests      []common.StackRequest
	deletedStacks []common.Stack
	location      common.ProvisionerLocation
}

func (p *fakeStackProvisioner) Name() string {
	return "fake"
}

func (p *fakeStackProvisioner) Location() common.ProvisionerLocation { return p.location }

func (p *fakeStackProvisioner) SetLogger(_ common.Logger) {
}

func (p *fakeStackProvisioner) Create(_ context.Context, request common.StackRequest) (common.Stack, error) {
	p.mx.Lock()
	defer p.mx.Unlock()
	p.requests = append(p.requests, request)
	return common.Stack{
		ID:                 request.ID,
		Version:            request.Version,
		Elasticsearch:      "http://localhost:9200",
		Kibana:             "http://localhost:5601",
		IntegrationsServer: "http://localhost:8220",
		Username:           "elastic",
		Password:           "changeme",
		Internal:           nil,
		Ready:              false,
	}, nil
}

func (p *fakeStackProvisioner) WaitForReady(_ context.Context, stack common.Stack) (common.Stack, error) {
	stack.Ready = true
	return stack, nil
}

func (p *fakeStackProvisioner) Delete(_ context.Context, stack common.Stack) error {
	p.mx.Lock()
	defer p.mx.Unlock()
	p.deletedStacks = append(p.deletedStacks, stack)
	return nil
}

func (p *fakeStackProvisioner) Upgrade(_ context.Context, _ common.Stack, _ string) error {
	// fake upgrade does nothing
	return nil
}
