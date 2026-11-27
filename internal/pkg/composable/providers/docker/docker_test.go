// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package docker

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/pkg/autodiscover/bus"
	"github.com/elastic/beats/v7/pkg/autodiscover/docker"
	"github.com/elastic/beats/v7/pkg/logp"
	"github.com/elastic/beats/v7/pkg/mapstr"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const connectSkipMessage = "Docker provider skipped, unable to connect"

type cancelComm struct {
	context.Context
}

func (cancelComm) AddOrUpdate(string, int, map[string]interface{}, []map[string]interface{}) error {
	return nil
}

func (cancelComm) Remove(string) {}

type fakeWatcher struct {
	startErr error
	stopped  atomic.Bool
	events   bus.Bus
}

func (f *fakeWatcher) Start() error { return f.startErr }
func (f *fakeWatcher) Stop()        { f.stopped.Store(true) }
func (f *fakeWatcher) Container(string) *docker.Container {
	return nil
}
func (f *fakeWatcher) Containers() map[string]*docker.Container { return nil }
func (f *fakeWatcher) ListenStart() bus.Listener                { return f.events.Subscribe() }
func (f *fakeWatcher) ListenStop() bus.Listener                 { return f.events.Subscribe() }

func testProvider(t *testing.T, retry time.Duration, factory watcherFactory) (*dynamicProvider, *bytes.Buffer) {
	t.Helper()
	log, buf := logger.NewInMemory("docker", logp.ConsoleEncoderConfig())
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("provider logs:\n%s", buf.String())
		}
	})
	return &dynamicProvider{
		logger:       log,
		config:       &Config{Host: "unix:///var/run/docker.sock", CleanupTimeout: time.Second},
		connectRetry: retry,
		newWatcher:   factory,
	}, buf
}

func TestRunRetriesUntilContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempted := make(chan struct{}, 1)
	p, buf := testProvider(t, time.Hour, func(*logger.Logger, string, *docker.TLSConfig, bool) (docker.Watcher, error) {
		select {
		case attempted <- struct{}{}:
		default:
		}
		return nil, errors.New("dial unix /var/run/docker.sock: connect: no such file or directory")
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Run(cancelComm{Context: ctx})
	}()

	select {
	case <-attempted:
	case <-time.After(2 * time.Second):
		t.Fatal("connect was not attempted")
	}
	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	info, debug := countSkipLogs(buf.String())
	assert.Equal(t, 1, info)
	assert.Equal(t, 0, debug)
}

func TestRunLogsFurtherConnectFailuresAtDebug(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	watching := make(chan struct{})
	var connected *fakeWatcher
	p, buf := testProvider(t, 5*time.Millisecond, func(log *logger.Logger, _ string, _ *docker.TLSConfig, _ bool) (docker.Watcher, error) {
		n := calls.Add(1)
		if n < 3 {
			return nil, errors.New("dial unix /var/run/docker.sock: connect: no such file or directory")
		}
		connected = &fakeWatcher{events: bus.New(log, "docker")}
		close(watching)
		return connected, nil
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Run(cancelComm{Context: ctx})
	}()

	select {
	case <-watching:
	case <-time.After(2 * time.Second):
		t.Fatalf("provider did not connect after retries, attempts=%d", calls.Load())
	}
	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	info, debug := countSkipLogs(buf.String())
	assert.Equal(t, 1, info, "first connect failure is info")
	assert.Equal(t, 1, debug, "second connect failure is debug")
	require.NotNil(t, connected)
	assert.True(t, connected.stopped.Load(), "watcher is stopped when the provider context is cancelled")
}

func countSkipLogs(logs string) (info int, debug int) {
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, connectSkipMessage) {
			continue
		}
		switch {
		case strings.Contains(line, "INFO"):
			info++
		case strings.Contains(line, "DEBUG"):
			debug++
		}
	}
	return info, debug
}

func TestSetRetryIntervalOverridesDefault(t *testing.T) {
	provider := &dynamicProvider{connectRetry: connectRetryInterval}
	require.Equal(t, connectRetryInterval, provider.retryInterval())

	provider.SetRetryInterval(5 * time.Millisecond)
	require.Equal(t, 5*time.Millisecond, provider.retryInterval())

	provider.SetRetryInterval(0)
	require.Equal(t, 5*time.Millisecond, provider.retryInterval())
}

func TestGenerateData(t *testing.T) {
	container := &docker.Container{
		ID:    "abc",
		Name:  "foobar",
		Image: "busybox:latest",
		Labels: map[string]string{
			"do.not.include":          "true",
			"co.elastic.logs/disable": "true",
		},
	}
	event := bus.Event{
		"container": container,
	}

	data, err := generateData(event)
	require.NoError(t, err)
	mapping := map[string]interface{}{
		"container": map[string]interface{}{
			"id":   container.ID,
			"name": container.Name,
			"image": map[string]interface{}{
				"name": container.Image,
			},
			"labels": mapstr.M{
				"do": mapstr.M{"not": mapstr.M{"include": "true"}},
				"co": mapstr.M{"elastic": mapstr.M{"logs/disable": "true"}},
			},
		},
	}
	processors := []map[string]interface{}{
		{
			"add_fields": map[string]interface{}{
				"fields": map[string]interface{}{
					"id":         container.ID,
					"name":       container.Name,
					"image.name": container.Image,
					"labels": mapstr.M{
						"do_not_include":          "true",
						"co_elastic_logs/disable": "true",
					},
				},
				"target": "container",
			},
		},
	}

	assert.Equal(t, container, data.container)
	assert.Equal(t, mapping, data.mapping)
	assert.Equal(t, processors, data.processors)
}
