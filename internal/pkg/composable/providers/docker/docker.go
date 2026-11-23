// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package docker

import (
	"fmt"
	"time"

	"github.com/elastic/beats/v7/pkg/autodiscover/bus"
	"github.com/elastic/beats/v7/pkg/autodiscover/docker"
	"github.com/elastic/beats/v7/pkg/autodiscover/utils"
	"github.com/elastic/beats/v7/pkg/mapstr"
	"github.com/elastic/beats/v7/pkg/safemapstr"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// ContainerPriority is the priority that container mappings are added to the provider.
const ContainerPriority = 0

// connectRetryInterval is how long Run waits before dialing Docker again after a
// connect failure. It matches composable.defaultRetryInterval. The retry stays
// inside Run so the controller does not log a provider crash every interval.
const connectRetryInterval = 30 * time.Second

// watcherFactory opens a Docker watcher. Tests replace it to simulate a missing daemon.
type watcherFactory func(log *logger.Logger, host string, tls *docker.TLSConfig, storeShortID bool) (docker.Watcher, error)

type dockerContainerData struct {
	container  *docker.Container
	mapping    map[string]interface{}
	processors []map[string]interface{}
}
type dynamicProvider struct {
	logger       *logger.Logger
	config       *Config
	connectRetry time.Duration
	newWatcher   watcherFactory
}

// Run runs the environment context provider.
func (c *dynamicProvider) Run(comm composable.DynamicProviderComm) error {
	logged := false
	for {
		watcher, err := c.openWatcher()
		if err != nil {
			if c.waitConnectRetry(comm, err, &logged) {
				return comm.Err()
			}
			continue
		}

		// Subscribe before Start. Start publishes the containers that already exist,
		// and those events are dropped if nobody is listening yet.
		startListener := watcher.ListenStart()
		stopListener := watcher.ListenStop()
		if err := watcher.Start(); err != nil {
			startListener.Stop()
			stopListener.Stop()
			watcher.Stop()
			if c.waitConnectRetry(comm, err, &logged) {
				return comm.Err()
			}
			continue
		}

		return c.watch(comm, watcher, startListener, stopListener)
	}
}

func (c *dynamicProvider) openWatcher() (docker.Watcher, error) {
	factory := c.newWatcher
	if factory == nil {
		factory = docker.NewWatcher
	}
	return factory(c.logger, c.config.Host, c.config.TLS, false)
}

// waitConnectRetry logs a connect failure and waits for the next attempt.
// It returns true when the provider context is done and Run must return.
func (c *dynamicProvider) waitConnectRetry(comm composable.DynamicProviderComm, err error, logged *bool) bool {
	if !*logged {
		c.logger.Infof("Docker provider skipped, unable to connect: %s", err)
		*logged = true
	} else {
		c.logger.Debugf("Docker provider skipped, unable to connect: %s", err)
	}

	timer := time.NewTimer(c.retryInterval())
	defer timer.Stop()
	select {
	case <-comm.Done():
		return true
	case <-timer.C:
		return false
	}
}

func (c *dynamicProvider) retryInterval() time.Duration {
	if c.connectRetry > 0 {
		return c.connectRetry
	}
	return connectRetryInterval
}

func (c *dynamicProvider) watch(comm composable.DynamicProviderComm, watcher docker.Watcher, startListener bus.Listener, stopListener bus.Listener) error {
	stoppers := map[string]*time.Timer{}
	stopTrigger := make(chan *dockerContainerData)
	defer watcher.Stop()

	for {
		select {
		case <-comm.Done():
			startListener.Stop()
			stopListener.Stop()

			// Stop all timers before closing the channel
			for _, stopper := range stoppers {
				stopper.Stop()
			}
			close(stopTrigger)
			return comm.Err()
		case event := <-startListener.Events():
			data, err := generateData(event)
			if err != nil {
				c.logger.Errorf("%s", err)
				continue
			}
			if stopper, ok := stoppers[data.container.ID]; ok {
				c.logger.Debugf("container %s is restarting, aborting pending stop", data.container.ID)
				stopper.Stop()
				delete(stoppers, data.container.ID)
				continue
			}
			err = comm.AddOrUpdate(data.container.ID, ContainerPriority, data.mapping, data.processors)
			if err != nil {
				c.logger.Errorf("%s", err)
			}
		case event := <-stopListener.Events():
			data, err := generateData(event)
			if err != nil {
				c.logger.Errorf("%s", err)
				continue
			}
			stopper := time.AfterFunc(c.config.CleanupTimeout, func() {
				stopTrigger <- data
			})
			stoppers[data.container.ID] = stopper
		case data := <-stopTrigger:
			delete(stoppers, data.container.ID)
			comm.Remove(data.container.ID)
		}
	}
}

// DynamicProviderBuilder builds the dynamic provider.
func DynamicProviderBuilder(logger *logger.Logger, c *config.Config, managed bool) (composable.DynamicProvider, error) {
	var cfg Config
	if c == nil {
		c = config.New()
	}
	err := c.UnpackTo(&cfg)
	if err != nil {
		return nil, errors.New(err, "failed to unpack configuration")
	}
	return &dynamicProvider{
		logger:       logger,
		config:       &cfg,
		connectRetry: connectRetryInterval,
		newWatcher:   docker.NewWatcher,
	}, nil
}

func generateData(event bus.Event) (*dockerContainerData, error) {
	container, ok := event["container"].(*docker.Container)
	if !ok {
		return nil, fmt.Errorf("unable to get container from watcher event")
	}

	labelMap := mapstr.M{}
	processorLabelMap := mapstr.M{}
	for k, v := range container.Labels {
		_ = safemapstr.Put(labelMap, k, v)
		_, _ = processorLabelMap.Put(utils.DeDot(k), v)
	}

	data := &dockerContainerData{
		container: container,
		mapping: map[string]interface{}{
			"container": map[string]interface{}{
				"id":   container.ID,
				"name": container.Name,
				"image": map[string]interface{}{
					"name": container.Image,
				},
				"labels": labelMap,
			},
		},
		processors: []map[string]interface{}{
			{
				"add_fields": map[string]interface{}{
					"fields": map[string]interface{}{
						"id":         container.ID,
						"name":       container.Name,
						"image.name": container.Image,
						"labels":     processorLabelMap,
					},
					"target": "container",
				},
			},
		},
	}
	return data, nil
}
