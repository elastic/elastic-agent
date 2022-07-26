// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"sort"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	apiStatusTimeout = 15 * time.Second
)

// PolicyChange is a handler for POLICY_CHANGE action.
type PolicyChange struct {
	log       *logger.Logger
	agentInfo *info.AgentInfo
	config    *configuration.Configuration
	store     storage.Store
	ch        chan coordinator.ConfigChange
	setters   []actions.ClientSetter
}

// NewPolicyChange creates a new PolicyChange handler.
func NewPolicyChange(
	log *logger.Logger,
	agentInfo *info.AgentInfo,
	config *configuration.Configuration,
	store storage.Store,
	ch chan coordinator.ConfigChange,
	setters ...actions.ClientSetter,
) *PolicyChange {
	return &PolicyChange{
		log:       log,
		agentInfo: agentInfo,
		config:    config,
		store:     store,
		ch:        ch,
		setters:   setters,
	}
}

// AddSetter adds a setter into a collection of client setters.
func (h *PolicyChange) AddSetter(cs actions.ClientSetter) {
	if h.setters == nil {
		h.setters = make([]actions.ClientSetter, 0)
	}

	h.setters = append(h.setters, cs)
}

// Handle handles policy change action.
func (h *PolicyChange) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Debugf("handlerPolicyChange: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionPolicyChange)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionPolicyChange and received %T", a)
	}

	c, err := config.NewConfigFrom(action.Policy)
	if err != nil {
		return errors.New(err, "could not parse the configuration from the policy", errors.TypeConfig)
	}

	h.log.Debugf("handlerPolicyChange: emit configuration for action %+v", a)
	err = h.handleFleetServerHosts(ctx, c)
	if err != nil {
		return err
	}

	h.ch <- &policyChange{
		ctx:    ctx,
		cfg:    c,
		action: a,
		acker:  acker,
	}
	return nil
}

// Watch returns the channel for configuration change notifications.
func (h *PolicyChange) Watch() <-chan coordinator.ConfigChange {
	return h.ch
}

func (h *PolicyChange) handleFleetServerHosts(ctx context.Context, c *config.Config) (err error) {
	// do not update fleet-server host from policy; no setters provided with local Fleet Server
	if len(h.setters) == 0 {
		return nil
	}
	data, err := c.ToMapStr()
	if err != nil {
		return errors.New(err, "could not convert the configuration from the policy", errors.TypeConfig)
	}
	if _, ok := data["fleet"]; !ok {
		// no fleet information in the configuration (skip checking client)
		return nil
	}

	cfg, err := configuration.NewFromConfig(c)
	if err != nil {
		return errors.New(err, "could not parse the configuration from the policy", errors.TypeConfig)
	}
	if clientEqual(h.config.Fleet.Client, cfg.Fleet.Client) {
		// already the same hosts
		return nil
	}

	// only set protocol/hosts as that is all Fleet currently sends
	prevProtocol := h.config.Fleet.Client.Protocol
	prevPath := h.config.Fleet.Client.Path
	prevHosts := h.config.Fleet.Client.Hosts
	h.config.Fleet.Client.Protocol = cfg.Fleet.Client.Protocol
	h.config.Fleet.Client.Path = cfg.Fleet.Client.Path
	h.config.Fleet.Client.Hosts = cfg.Fleet.Client.Hosts

	// rollback on failure
	defer func() {
		if err != nil {
			h.config.Fleet.Client.Protocol = prevProtocol
			h.config.Fleet.Client.Path = prevPath
			h.config.Fleet.Client.Hosts = prevHosts
		}
	}()

	client, err := client.NewAuthWithConfig(h.log, h.config.Fleet.AccessAPIKey, h.config.Fleet.Client)
	if err != nil {
		return errors.New(
			err, "fail to create API client with updated hosts",
			errors.TypeNetwork, errors.M("hosts", h.config.Fleet.Client.Hosts))
	}
	ctx, cancel := context.WithTimeout(ctx, apiStatusTimeout)
	defer cancel()
	resp, err := client.Send(ctx, "GET", "/api/status", nil, nil, nil)
	if err != nil {
		return errors.New(
			err, "fail to communicate with updated API client hosts",
			errors.TypeNetwork, errors.M("hosts", h.config.Fleet.Client.Hosts))
	}
	// discard body for proper cancellation and connection reuse
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()

	reader, err := fleetToReader(h.agentInfo, h.config)
	if err != nil {
		return errors.New(
			err, "fail to persist updated API client hosts",
			errors.TypeUnexpected, errors.M("hosts", h.config.Fleet.Client.Hosts))
	}
	err = h.store.Save(reader)
	if err != nil {
		return errors.New(
			err, "fail to persist updated API client hosts",
			errors.TypeFilesystem, errors.M("hosts", h.config.Fleet.Client.Hosts))
	}
	for _, setter := range h.setters {
		setter.SetClient(client)
	}
	return nil
}

func clientEqual(k1 remote.Config, k2 remote.Config) bool {
	if k1.Protocol != k2.Protocol {
		return false
	}
	if k1.Path != k2.Path {
		return false
	}

	sort.Strings(k1.Hosts)
	sort.Strings(k2.Hosts)
	if len(k1.Hosts) != len(k2.Hosts) {
		return false
	}
	for i, v := range k1.Hosts {
		if v != k2.Hosts[i] {
			return false
		}
	}
	return true
}

func fleetToReader(agentInfo *info.AgentInfo, cfg *configuration.Configuration) (io.Reader, error) {
	configToStore := map[string]interface{}{
		"fleet": cfg.Fleet,
		"agent": map[string]interface{}{
			"id":               agentInfo.AgentID(),
			"logging.level":    cfg.Settings.LoggingConfig.Level,
			"monitoring.http":  cfg.Settings.MonitoringConfig.HTTP,
			"monitoring.pprof": cfg.Settings.MonitoringConfig.Pprof,
		},
	}

	data, err := yaml.Marshal(configToStore)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

type policyChange struct {
	ctx    context.Context
	cfg    *config.Config
	action fleetapi.Action
	acker  acker.Acker
	commit bool
}

func (l *policyChange) Config() *config.Config {
	return l.cfg
}

func (l *policyChange) Ack() error {
	if l.action == nil {
		return nil
	}
	err := l.acker.Ack(l.ctx, l.action)
	if err != nil {
		return err
	}
	if l.commit {
		return l.acker.Commit(l.ctx)
	}
	return nil
}

func (l *policyChange) Fail(_ error) {
	// do nothing
}
