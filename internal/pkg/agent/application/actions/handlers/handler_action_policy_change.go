// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	fleetclient "github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	apiStatusTimeout = 15 * time.Second
)

// PolicyChangeHandler is a handler for POLICY_CHANGE action.
type PolicyChangeHandler struct {
	log       *logger.Logger
	agentInfo info.Agent
	config    *configuration.Configuration
	store     storage.Store
	ch        chan coordinator.ConfigChange
	setters   []actions.ClientSetter

	// Disabled for 8.8.0 release in order to limit the surface
	// https://github.com/elastic/security-team/issues/6501
	// // Last known valid signature validation key
	// signatureValidationKey []byte
}

// NewPolicyChangeHandler creates a new PolicyChange handler.
func NewPolicyChangeHandler(
	log *logger.Logger,
	agentInfo info.Agent,
	config *configuration.Configuration,
	store storage.Store,
	ch chan coordinator.ConfigChange,
	setters ...actions.ClientSetter,
) *PolicyChangeHandler {
	return &PolicyChangeHandler{
		log:       log,
		agentInfo: agentInfo,
		config:    config,
		store:     store,
		ch:        ch,
		setters:   setters,
	}
}

// AddSetter adds a setter into a collection of client setters.
func (h *PolicyChangeHandler) AddSetter(cs actions.ClientSetter) {
	if h.setters == nil {
		h.setters = make([]actions.ClientSetter, 0)
	}

	h.setters = append(h.setters, cs)
}

// Handle handles policy change action.
func (h *PolicyChangeHandler) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Debugf("handlerPolicyChange: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionPolicyChange)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionPolicyChange and received %T", a)
	}

	// Disabled for 8.8.0 release in order to limit the surface
	// https://github.com/elastic/security-team/issues/6501

	// // Validate policy signature and overlay signed configuration
	// policy, signatureValidationKey, err := protection.ValidatePolicySignature(h.log, action.Policy, h.signatureValidationKey)
	// if err != nil {
	// 	return errors.New(err, "could not validate the policy signed configuration", errors.TypeConfig)
	// }
	// h.log.Debugf("handlerPolicyChange: policy validation result: signature validation key length: %v, err: %v", len(signatureValidationKey), err)

	// // Cache signature validation key for the next policy handling
	// h.signatureValidationKey = signatureValidationKey

	c, err := config.NewConfigFrom(action.Policy)
	if err != nil {
		return errors.New(err, "could not parse the configuration from the policy", errors.TypeConfig)
	}

	h.log.Debugf("handlerPolicyChange: emit configuration for action %+v", a)
	err = h.handleFleetServerConfig(ctx, c)
	if err != nil {
		return err
	}

	h.ch <- newPolicyChange(ctx, c, a, acker, false)
	return nil
}

// Watch returns the channel for configuration change notifications.
func (h *PolicyChangeHandler) Watch() <-chan coordinator.ConfigChange {
	return h.ch
}

func (h *PolicyChangeHandler) handleFleetServerConfig(ctx context.Context, c *config.Config) (err error) {
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

	prevProtocol := h.config.Fleet.Client.Protocol
	prevPath := h.config.Fleet.Client.Path
	prevHost := h.config.Fleet.Client.Host
	prevHosts := h.config.Fleet.Client.Hosts
	prevProxy := h.config.Fleet.Client.Transport.Proxy

	var prevTLSNil bool
	var prevCAs []string
	var prevCertificateCfg tlscommon.CertificateConfig
	if h.config.Fleet.Client.Transport.TLS != nil {
		prevTLSNil = false
		prevCAs = h.config.Fleet.Client.Transport.TLS.CAs
		prevCertificateCfg = h.config.Fleet.Client.Transport.TLS.Certificate
	} else {
		prevTLSNil = true
	}
	// rollback on failure
	defer func() {
		if err != nil {
			h.config.Fleet.Client.Protocol = prevProtocol
			h.config.Fleet.Client.Path = prevPath
			h.config.Fleet.Client.Host = prevHost
			h.config.Fleet.Client.Hosts = prevHosts
			h.config.Fleet.Client.Transport.Proxy = prevProxy
			if prevTLSNil {
				h.config.Fleet.Client.Transport.TLS = nil
			} else {
				h.config.Fleet.Client.Transport.TLS.CAs = prevCAs
				h.config.Fleet.Client.Transport.TLS.Certificate = prevCertificateCfg
			}
			h.log.Debugf("an error happened, reverting fleet-server config")
		}
	}()

	h.applyConfigWithPrecedence(cfg.Fleet.Client)

	client, err := fleetclient.NewAuthWithConfig(
		h.log, h.config.Fleet.AccessAPIKey, h.config.Fleet.Client)
	if err != nil {
		return errors.New(
			err, "fail to create API client with updated config",
			errors.TypeConfig,
			errors.M("hosts", append(
				h.config.Fleet.Client.Hosts, h.config.Fleet.Client.Host)))
	}

	ctx, cancel := context.WithTimeout(ctx, apiStatusTimeout)
	defer cancel()

	resp, err := client.Send(ctx, http.MethodGet, "/api/status", nil, nil, nil)
	if err != nil {
		return errors.New(
			err, "fail to communicate with Fleet Server API client hosts",
			errors.TypeNetwork, errors.M("hosts", h.config.Fleet.Client.Hosts))
	}

	// discard body for proper cancellation and connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	reader, err := fleetToReader(h.agentInfo, h.config)
	if err != nil {
		return errors.New(
			err, "fail to persist new Fleet Server API client hosts",
			errors.TypeUnexpected, errors.M("hosts", h.config.Fleet.Client.Hosts))
	}

	err = h.store.Save(reader)
	if err != nil {
		return errors.New(
			err, "fail to persist new Fleet Server API client hosts",
			errors.TypeFilesystem, errors.M("hosts", h.config.Fleet.Client.Hosts))
	}

	for _, setter := range h.setters {
		setter.SetClient(client)
	}
	return nil
}

// applyConfigWithPrecedence applies Proxy and TLS configs, but ignores empty ones.
// That way a proxy or TLS config set during install/enroll using cli flags
// won't be overridden by an absent or empty proxy from fleet-server.
// However, if there is a proxy or TLS config sent by fleet-server, it'll take
// precedence. Therefore, it's not possible to remove a proxy or TLS config once
// it's set.
func (h *PolicyChangeHandler) applyConfigWithPrecedence(cfg remote.Config) {
	defaultcfg := configuration.DefaultFleetAgentConfig()

	if cfg.Protocol != defaultcfg.Client.Protocol ||
		cfg.Host != defaultcfg.Client.Host ||
		!slices.Equal(cfg.Hosts, defaultcfg.Client.Hosts) ||
		cfg.Path != defaultcfg.Client.Path {
		h.config.Fleet.Client.Protocol = cfg.Protocol
		h.config.Fleet.Client.Path = cfg.Path
		h.config.Fleet.Client.Host = cfg.Host
		h.config.Fleet.Client.Hosts = cfg.Hosts
	}

	if cfg.Transport.Proxy.URL == nil ||
		cfg.Transport.Proxy.URL.String() == "" {
		h.log.Debug("proxy from fleet is empty or null, the proxy will not be changed")
	} else {
		h.config.Fleet.Client.Transport.Proxy = cfg.Transport.Proxy
		h.log.Debug("received proxy from fleet, applying it")
	}

	emptyCertificate := tlscommon.CertificateConfig{}
	if cfg.Transport.TLS != nil {
		if h.config.Fleet.Client.Transport.TLS == nil {
			h.config.Fleet.Client.Transport.TLS = &tlscommon.Config{}
		}

		if cfg.Transport.TLS.Certificate == emptyCertificate {
			h.log.Debug("TLS certificates from fleet are empty or null, the TLS config will not be changed")
		} else {
			h.config.Fleet.Client.Transport.TLS.Certificate = cfg.Transport.TLS.Certificate
			h.log.Debug("received SSL from fleet, applying it")
		}

		// apply an empty CA
		if cfg.Transport.TLS.CAs == nil {
			h.log.Debug("TLS CAs from fleet are empty or null, the TLS config will not be changed")
		} else {
			h.config.Fleet.Client.Transport.TLS.CAs = cfg.Transport.TLS.CAs
			h.log.Debug("received SSL from fleet, applying it")
		}
	}
}

func clientEqual(current remote.Config, new remote.Config) bool {
	if new.Protocol != "" &&
		current.Protocol != new.Protocol {
		return false
	}
	if new.Path != "" &&
		current.Path != new.Path {
		return false
	}

	sort.Strings(current.Hosts)
	sort.Strings(new.Hosts)
	if len(current.Hosts) != len(new.Hosts) {
		return false
	}
	for i, v := range current.Hosts {
		if v != new.Hosts[i] {
			return false
		}
	}

	// should it ignore empty headers?
	headersEqual := func(h1, h2 httpcommon.ProxyHeaders) bool {
		if len(h1) != len(h2) {
			return false
		}

		for k, v := range h1 {
			h2v, found := h2[k]
			if !found || v != h2v {
				return false
			}
		}

		return true
	}

	// different proxy
	if new.Transport.Proxy.URL != nil &&
		current.Transport.Proxy.URL != new.Transport.Proxy.URL ||
		current.Transport.Proxy.Disable != new.Transport.Proxy.Disable ||
		!headersEqual(current.Transport.Proxy.Headers, new.Transport.Proxy.Headers) {
		return false
	}

	// different TLS config
	if len(new.Transport.TLS.CAs) > 0 &&
		!slices.Equal(current.Transport.TLS.CAs, new.Transport.TLS.CAs) {
		return false
	}

	emptyCert := tlscommon.CertificateConfig{}
	if new.Transport.TLS.Certificate != emptyCert &&
		current.Transport.TLS.Certificate != new.Transport.TLS.Certificate {
		return false
	}

	return true
}

func fleetToReader(agentInfo info.Agent, cfg *configuration.Configuration) (io.Reader, error) {
	configToStore := map[string]interface{}{
		"fleet": cfg.Fleet,
		"agent": map[string]interface{}{
			"id":               agentInfo.AgentID(),
			"headers":          agentInfo.Headers(),
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
	ctx        context.Context
	cfg        *config.Config
	action     fleetapi.Action
	acker      acker.Acker
	commit     bool
	ackWatcher chan struct{}
}

func newPolicyChange(
	ctx context.Context,
	config *config.Config,
	action fleetapi.Action,
	acker acker.Acker,
	commit bool) *policyChange {
	var ackWatcher chan struct{}
	if commit {
		// we don't need it otherwise
		ackWatcher = make(chan struct{})
	}
	return &policyChange{
		ctx:        ctx,
		cfg:        config,
		action:     action,
		acker:      acker,
		commit:     true,
		ackWatcher: ackWatcher,
	}
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
		err := l.acker.Commit(l.ctx)
		if l.ackWatcher != nil && err == nil {
			close(l.ackWatcher)
		}
		return err
	}
	return nil
}

// WaitAck waits for policy change to be acked.
// Policy change ack is awaitable only in case commit flag was set.
// Caller is responsible to use any reasonable deadline otherwise
// function call can be endlessly blocking.
func (l *policyChange) WaitAck(ctx context.Context) {
	if !l.commit || l.ackWatcher == nil {
		return
	}

	select {
	case <-l.ackWatcher:
	case <-ctx.Done():
	}
}

func (l *policyChange) Fail(_ error) {
	// do nothing
}
