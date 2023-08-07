package runner

import (
	"context"
	"os"
	"path/filepath"
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
		AgentVersion:      "8.10.0",
		AgentStackVersion: "8.10.0-SNAPSHOT",
		BuildDir:          filepath.Join(tmpdir, "build"),
		GOVersion:         "1.20.7",
		RepoDir:           filepath.Join(tmpdir, "repo"),
		StateDir:          stateDir,
		ExtraEnv:          nil,
	}
	ip := &fakeInstanceProvisioner{}
	sp := &fakeStackProvisioner{}
	r, err := NewRunner(cfg, ip, sp)
	require.NoError(t, err)

	i1 := Instance{
		ID:         "id-1",
		Name:       "name-1",
		IP:         "127.0.0.1",
		Username:   "ubuntu",
		RemotePath: "/home/ubuntu/agent",
		Internal:   map[string]interface{}{}, // ElementsMatch fails without this set
	}
	err = r.addOrUpdateInstance(StateInstance{
		Instance: i1,
		Prepared: true,
	})
	require.NoError(t, err)
	i2 := Instance{
		ID:         "id-2",
		Name:       "name-2",
		IP:         "127.0.0.2",
		Username:   "ubuntu",
		RemotePath: "/home/ubuntu/agent",
		Internal:   map[string]interface{}{}, // ElementsMatch fails without this set
	}
	err = r.addOrUpdateInstance(StateInstance{
		Instance: i2,
		Prepared: true,
	})
	require.NoError(t, err)
	s1 := Stack{
		ID:       "id-1",
		Version:  "8.10.0",
		Internal: map[string]interface{}{}, // ElementsMatch fails without this set
	}
	err = r.addOrUpdateStack(s1)
	require.NoError(t, err)
	s2 := Stack{
		ID:       "id-2",
		Version:  "8.9.0",
		Internal: map[string]interface{}{}, // ElementsMatch fails without this set
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
	assert.ElementsMatch(t, sp.stacks, []Stack{s1, s2})
}

type fakeInstanceProvisioner struct {
	batches   []OSBatch
	instances []Instance
}

func (f *fakeInstanceProvisioner) SetLogger(_ Logger) {
}

func (f *fakeInstanceProvisioner) Supported(_ define.OS) bool {
	return true
}

func (f *fakeInstanceProvisioner) Provision(_ context.Context, _ Config, batches []OSBatch) ([]Instance, error) {
	f.batches = batches
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

func (f *fakeInstanceProvisioner) Clean(_ context.Context, _ Config, instances []Instance) error {
	f.instances = instances
	return nil
}

type fakeStackProvisioner struct {
	requests []StackRequest
	stacks   []Stack
}

func (f *fakeStackProvisioner) SetLogger(_ Logger) {
}

func (f *fakeStackProvisioner) Provision(_ context.Context, requests []StackRequest) ([]Stack, error) {
	f.requests = requests
	var stacks []Stack
	for _, req := range requests {
		stacks = append(stacks, Stack{
			ID:            req.ID,
			Version:       req.Version,
			Elasticsearch: "http://localhost:9200",
			Kibana:        "http://localhost:5601",
			Username:      "elastic",
			Password:      "changeme",
			Internal:      nil,
		})
	}
	return stacks, nil
}

func (f *fakeStackProvisioner) Clean(_ context.Context, stacks []Stack) error {
	f.stacks = stacks
	return nil
}
