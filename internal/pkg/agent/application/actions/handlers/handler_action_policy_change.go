// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"bytes"
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"sort"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/elastic-agent/pkg/fleetapi"
)

// PolicyChangeHandler is a handler for POLICY_CHANGE action.
type PolicyChangeHandler struct {
	log                   *logger.Logger
	agentInfo             info.Agent
	fallbackConfig        *configuration.Configuration
	config                *configuration.Configuration
	store                 storage.Store
	stateStore            stateStore
	ch                    chan coordinator.ConfigChange
	setters               []actions.ClientSetter
	runtimeLogLevelSetter logLevelSetter
	disableAckFn          func() bool
	// Disabled for 8.8.0 release in order to limit the surface
	// https://github.com/elastic/security-team/issues/6501
	// // Last known valid signature validation key
	// signatureValidationKey []byte
}

// NewPolicyChangeHandler creates a new PolicyChange handler.
func NewPolicyChangeHandler(
	log *logger.Logger,
	agentInfo info.Agent,
	fallbackConfig *configuration.Configuration,
	config *configuration.Configuration,
	store storage.Store,
	stateStore stateStore,
	ch chan coordinator.ConfigChange,
	runtimeLogLevelSetter logLevelSetter,
	setters ...actions.ClientSetter,
) *PolicyChangeHandler {
	return &PolicyChangeHandler{
		log:                   log,
		agentInfo:             agentInfo,
		fallbackConfig:        fallbackConfig,
		config:                config,
		store:                 store,
		stateStore:            stateStore,
		ch:                    ch,
		setters:               setters,
		runtimeLogLevelSetter: runtimeLogLevelSetter,
		disableAckFn:          features.DisablePolicyChangeAcks,
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

	c, err := config.NewConfigFrom(action.Data.Policy)
	if err != nil {
		return errors.New(err, "could not parse the configuration from the policy", errors.TypeConfig)
	}

	h.log.Debugf("handlerPolicyChange: emit configuration for action %+v", a)
	err = h.handlePolicyChange(ctx, c, action)
	if err != nil {
		return err
	}

	h.ch <- newPolicyChange(ctx, h.log, c, a, acker, false, h.disableAckFn())
	return nil
}

// Watch returns the channel for configuration change notifications.
func (h *PolicyChangeHandler) Watch() <-chan coordinator.ConfigChange {
	return h.ch
}

func (h *PolicyChangeHandler) validateFleetServerHosts(ctx context.Context, cfg *configuration.Configuration) (*remote.Config, error) {
	// do not update fleet-server host from policy; no setters provided with local Fleet Server
	if len(h.setters) == 0 {
		return nil, nil
	}

	if cfg.Fleet == nil {
		// there is no client config (weird)
		return nil, nil
	}

	if clientEqual(h.config.Fleet.Client, cfg.Fleet.Client) {
		// already the same hosts
		return nil, nil
	}

	// make a copy the current client config and apply the changes on this copy
	newFleetClientConfig := h.config.Fleet.Client
	updateFleetConfig(h.log, cfg.Fleet.Client, &newFleetClientConfig)

	// Test new config
	err := testFleetConfig(ctx, h.log, newFleetClientConfig, h.config.Fleet.AccessAPIKey)
	if err != nil {
		return nil, fmt.Errorf("validating fleet client config: %w", err)
	}

	return &newFleetClientConfig, nil
}

func testFleetConfig(ctx context.Context, log *logger.Logger, clientConfig remote.Config, apiKey string) error {
	fleetClient, err := client.NewAuthWithConfig(
		log, apiKey, clientConfig)
	if err != nil {
		return errors.New(
			err, "fail to create API client with updated config",
			errors.TypeConfig,
			errors.M("hosts", append(
				clientConfig.Hosts, clientConfig.Host)))
	}

	return client.CheckRemote(ctx, fleetClient)
}

// updateFleetConfig copies the relevant Fleet client settings from policyConfig on agentConfig. The destination struct is modified in-place
func updateFleetConfig(log *logger.Logger, policyConfig remote.Config, agentConfig *remote.Config) {

	// Hosts is the only connectivity field sent Fleet, let's clear everything else aside from Hosts
	if len(policyConfig.Hosts) > 0 {
		agentConfig.Hosts = make([]string, len(policyConfig.Hosts))
		copy(agentConfig.Hosts, policyConfig.Hosts)

		agentConfig.Host = ""
		agentConfig.Protocol = ""
		agentConfig.Path = ""
	}

	// Empty proxies from fleet are ignored. That way a proxy set by --proxy-url
	// it won't be overridden by an absent or empty proxy from fleet-server.
	// However, if there is a proxy sent by fleet-server, it'll take precedence.
	// Therefore, it's not possible to remove a proxy once it's set.

	if policyConfig.Transport.Proxy.URL == nil ||
		policyConfig.Transport.Proxy.URL.String() == "" {
		log.Debugw("proxy from fleet is empty or null, the proxy will not be changed", "current_proxy", agentConfig.Transport.Proxy.URL)
	} else {
		log.Debugw("received proxy from fleet, applying it", "old_proxy", agentConfig.Transport.Proxy.URL, "new_proxy", policyConfig.Transport.Proxy.URL)
		// copy the proxy struct
		agentConfig.Transport.Proxy = policyConfig.Transport.Proxy

		// replace in agentConfig the attributes that are passed by reference within the proxy struct

		// Headers map
		agentConfig.Transport.Proxy.Headers = map[string]string{}
		for k, v := range policyConfig.Transport.Proxy.Headers {
			agentConfig.Transport.Proxy.Headers[k] = v
		}

		// Proxy URL
		urlCopy := *policyConfig.Transport.Proxy.URL
		agentConfig.Transport.Proxy.URL = &urlCopy
	}

	if policyConfig.Transport.TLS != nil {

		tlsCopy := tlscommon.Config{}
		if agentConfig.Transport.TLS != nil {
			// copy the TLS struct
			tlsCopy = *agentConfig.Transport.TLS
		}

		if policyConfig.Transport.TLS.Certificate == emptyCertificateConfig() {
			log.Debug("TLS certificates from fleet are empty or null, the TLS config will not be changed")
		} else {
			tlsCopy.Certificate = policyConfig.Transport.TLS.Certificate
			log.Debug("received TLS certificate/key from fleet, applying it")
		}

		if len(policyConfig.Transport.TLS.CAs) == 0 {
			log.Debug("TLS CAs from fleet are empty or null, the TLS config will not be changed")
		} else {
			tlsCopy.CAs = make([]string, len(policyConfig.Transport.TLS.CAs))
			copy(tlsCopy.CAs, policyConfig.Transport.TLS.CAs)
			log.Debug("received TLS CAs from fleet, applying it")
		}

		agentConfig.Transport.TLS = &tlsCopy
	}
}

func emptyCertificateConfig() tlscommon.CertificateConfig {
	return tlscommon.CertificateConfig{}
}

func (h *PolicyChangeHandler) handlePolicyChange(ctx context.Context, c *config.Config, action *fleetapi.ActionPolicyChange) error {
	partialCfg, err := configuration.NewPartialFromConfigNoDefaults(c)
	if err != nil {
		return fmt.Errorf("parsing fleet config: %w", err)
	}

	// Step 1: Validate policy configuration.
	var validationErr error
	validatedFleetConfig, err := h.validateFleetServerHosts(ctx, partialCfg)
	if err != nil {
		validationErr = goerrors.Join(validationErr, fmt.Errorf("failed to validate Fleet client config: %w", err))
	}
	loggingConfig, err := validateLoggingConfig(partialCfg)
	if err != nil {
		validationErr = goerrors.Join(validationErr, fmt.Errorf("failed to validate logging config: %w", err))
	}
	if validationErr != nil {
		return validationErr
	}

	// Step 2: Parse the incoming policy configuration.
	cfg, err := h.parsePolicyConfiguration(c)
	if err != nil {
		return fmt.Errorf("failed to parse policy configuration: %w", err)
	}

	// Step 3: Set the policy log level, the runtime step below reads it back.
	policyLogLevel := logger.DefaultLogLevel.String()
	if loggingConfig != nil {
		policyLogLevel = loggingConfig.Level.String()
	}
	h.agentInfo.SetLogLevelPolicy(policyLogLevel)

	// Step 4: Apply runtime changes before persisting, so a failure leaves
	// fleet.enc and the state store untouched.
	var runtimeErr error
	if err := h.applyFleetClientConfig(validatedFleetConfig); err != nil {
		runtimeErr = goerrors.Join(runtimeErr, fmt.Errorf("failed to apply Fleet client config: %w", err))
	}

	var logLevelRuntime logp.Level
	logLevelRuntimeStr := h.agentInfo.GetLogLevelRuntime()
	if err := logLevelRuntime.Unpack(logLevelRuntimeStr); err != nil {
		runtimeErr = goerrors.Join(runtimeErr, fmt.Errorf("failed to unpack runtime log level %q: %w", logLevelRuntimeStr, err))
	} else {
		h.log.Infof("Policy change done, setting agent log level to %s", logLevelRuntime)
		if err := h.runtimeLogLevelSetter.SetLogLevel(ctx, &logLevelRuntime); err != nil {
			runtimeErr = goerrors.Join(runtimeErr, fmt.Errorf("failed to set runtime log level: %w", err))
		}
	}
	if runtimeErr != nil {
		return runtimeErr
	}

	// Step 5: Commit. Both writes must succeed; Fleet re-delivers the action on
	// the next checkin if either fails.
	//
	// If saveConfig succeeds but SaveAction fails, fleet.enc holds the new config
	// while state.enc still records the old action. On restart Fleet re-delivers
	// the policy and the agent re-applies it; this is safe because policies are
	// idempotent.
	patch, needsReExec := h.buildConfigPatch(cfg, partialCfg, validatedFleetConfig, loggingConfig)

	if err := saveConfig(h.agentInfo, h.configWithPatch(patch), h.store, h.log); err != nil {
		return fmt.Errorf("failed to persist policy config: %w", err)
	}
	if h.stateStore != nil {
		if err := h.stateStore.SaveAction(action); err != nil {
			return fmt.Errorf("failed to persist policy action to state store: %w", err)
		}
	}

	h.commitConfig(patch)
	if needsReExec {
		h.runtimeLogLevelSetter.ReExec(nil)
	}

	return nil
}

func (h *PolicyChangeHandler) parsePolicyConfiguration(c *config.Config) (*configuration.Configuration, error) {
	if h.fallbackConfig == nil {
		return configuration.NewFromConfig(c)
	}

	cfg := configuration.DefaultConfiguration()
	if h.fallbackConfig.Settings.LoggingConfig != nil {
		loggingConfig := *h.fallbackConfig.Settings.LoggingConfig
		cfg.Settings.LoggingConfig = &loggingConfig
	}
	if h.fallbackConfig.Settings.EventLoggingConfig != nil {
		eventLoggingConfig := *h.fallbackConfig.Settings.EventLoggingConfig
		cfg.Settings.EventLoggingConfig = &eventLoggingConfig
	}

	if err := c.UnpackTo(cfg); err != nil {
		return nil, errors.New(err, errors.TypeConfig)
	}
	cfg.UCfg = c

	return cfg, nil
}

// configPatch holds the pending new values for h.config fields that
// handlePolicyChange may update.
type configPatch struct {
	eventLogging    logger.Config
	logging         logger.Config
	fleetClient     remote.Config
	monitoringHTTP  *monitoringCfg.MonitoringHTTPConfig
	monitoringPprof *monitoringCfg.PprofConfig
}

// buildConfigPatch computes the pending config values from the incoming policy.
// Returns the patch and whether a re-exec is needed.
func (h *PolicyChangeHandler) buildConfigPatch(
	cfg *configuration.Configuration,
	partialCfg *configuration.Configuration,
	validatedFleetConfig *remote.Config,
	loggingConfig *logger.Config,
) (configPatch, bool) {
	patch := configPatch{
		eventLogging:    *h.config.Settings.EventLoggingConfig,
		logging:         *h.config.Settings.LoggingConfig,
		fleetClient:     h.config.Fleet.Client,
		monitoringHTTP:  h.config.Settings.MonitoringConfig.HTTP,
		monitoringPprof: h.config.Settings.MonitoringConfig.Pprof,
	}
	needsReExec := false

	// Event logging output change.
	if (h.fallbackConfig != nil || (partialCfg != nil &&
		partialCfg.Settings != nil &&
		partialCfg.Settings.EventLoggingConfig != nil)) &&
		cfg != nil &&
		cfg.Settings != nil &&
		cfg.Settings.EventLoggingConfig != nil {
		incoming := cfg.Settings.EventLoggingConfig
		if patch.eventLogging.ToFiles != incoming.ToFiles || patch.eventLogging.ToStderr != incoming.ToStderr {
			patch.eventLogging.ToFiles = incoming.ToFiles
			patch.eventLogging.ToStderr = incoming.ToStderr
			needsReExec = true
		}
	}

	// Logging output change (ToFiles/ToStderr/Files.Path drive re-exec; Level is set separately).
	if (h.fallbackConfig != nil || loggingConfig != nil) &&
		cfg != nil &&
		cfg.Settings != nil &&
		cfg.Settings.LoggingConfig != nil {
		incoming := cfg.Settings.LoggingConfig
		if patch.logging.ToFiles != incoming.ToFiles ||
			patch.logging.ToStderr != incoming.ToStderr ||
			patch.logging.Files.Path != incoming.Files.Path {
			patch.logging.ToFiles = incoming.ToFiles
			patch.logging.ToStderr = incoming.ToStderr
			patch.logging.Files.Path = incoming.Files.Path
			needsReExec = true
		}
	}
	if loggingConfig != nil {
		patch.logging.Level = loggingConfig.Level
	}

	// Fleet client.
	if validatedFleetConfig != nil {
		patch.fleetClient = *validatedFleetConfig
	}

	// Monitoring config — only override when the policy explicitly carries the
	// section (partialCfg is unpacked without defaults, so nil means absent).
	// This preserves locally configured values (e.g. agent.monitoring.http.host)
	// instead of clobbering them with library defaults on every policy check-in.
	// See https://github.com/elastic/elastic-agent/issues/4582.
	if partialCfg != nil && partialCfg.Settings != nil && partialCfg.Settings.MonitoringConfig != nil {
		if partialCfg.Settings.MonitoringConfig.HTTP != nil {
			patch.monitoringHTTP = partialCfg.Settings.MonitoringConfig.HTTP
		}
		if partialCfg.Settings.MonitoringConfig.Pprof != nil {
			patch.monitoringPprof = partialCfg.Settings.MonitoringConfig.Pprof
		}
	}

	return patch, needsReExec
}

// configWithPatch returns a copy of h.config with the patch fields applied.
func (h *PolicyChangeHandler) configWithPatch(patch configPatch) *configuration.Configuration {
	cfgCopy := *h.config
	settingsCopy := *h.config.Settings
	cfgCopy.Settings = &settingsCopy

	eventLoggingCopy := patch.eventLogging
	settingsCopy.EventLoggingConfig = &eventLoggingCopy

	loggingCopy := patch.logging
	settingsCopy.LoggingConfig = &loggingCopy

	// Fleet is a shared pointer after the shallow copy; isolate before modifying Client.
	fleetCopy := *h.config.Fleet
	cfgCopy.Fleet = &fleetCopy
	fleetCopy.Client = patch.fleetClient

	// MonitoringConfig is likewise a shared pointer; isolate before replacing HTTP and Pprof.
	monitoringCopy := *h.config.Settings.MonitoringConfig
	settingsCopy.MonitoringConfig = &monitoringCopy
	monitoringCopy.HTTP = patch.monitoringHTTP
	monitoringCopy.Pprof = patch.monitoringPprof

	return &cfgCopy
}

// commitConfig applies the patch to h.config.
func (h *PolicyChangeHandler) commitConfig(patch configPatch) {
	*h.config.Settings.EventLoggingConfig = patch.eventLogging
	*h.config.Settings.LoggingConfig = patch.logging
	h.config.Fleet.Client = patch.fleetClient
	h.config.Settings.MonitoringConfig.HTTP = patch.monitoringHTTP
	h.config.Settings.MonitoringConfig.Pprof = patch.monitoringPprof
}

func validateLoggingConfig(cfg *configuration.Configuration) (*logger.Config, error) {
	if cfg == nil || cfg.Settings == nil || cfg.Settings.LoggingConfig == nil {
		// no logging config, nothing to do
		return nil, nil
	}

	loggingConfig := cfg.Settings.LoggingConfig
	logLevel := loggingConfig.Level
	if logLevel < logp.DebugLevel || logLevel > logp.CriticalLevel {
		return nil, fmt.Errorf("unrecognized log level %d", logLevel)
	}

	return loggingConfig, nil
}

func (h *PolicyChangeHandler) applyFleetClientConfig(validatedConfig *remote.Config) error {
	if validatedConfig == nil || len(h.setters) == 0 {
		// nothing to do for fleet hosts
		return nil
	}

	// the config has already been validated, no need for error handling
	fleetClient, err := client.NewAuthWithConfig(
		h.log, h.config.Fleet.AccessAPIKey, *validatedConfig)
	if err != nil {
		return fmt.Errorf("creating new fleet client with updated config: %w", err)
	}
	for _, setter := range h.setters {
		setter.SetClient(fleetClient)
	}

	return nil
}

func saveConfig(agentInfo info.Agent, validatedConfig *configuration.Configuration, store storage.Store, log *logger.Logger) error {
	if validatedConfig == nil {
		// nothing to do for fleet hosts
		return nil
	}
	reader, err := fleetToReader(agentInfo.AgentID(), agentInfo.Headers(), agentInfo.GetLogLevelOverride(), validatedConfig)
	if err != nil {
		return errors.New(
			err, "fail to persist new Fleet Server API client hosts",
			errors.TypeUnexpected, errors.M("hosts", validatedConfig.Fleet.Client.Hosts))
	}
	if err := saveConfigToStore(store, reader, log); err != nil {
		return errors.New(
			err, "fail to persist new Fleet Server API client hosts",
			errors.TypeFilesystem, errors.M("hosts", validatedConfig.Fleet.Client.Hosts))
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

	if k1.Host != k2.Host {
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
	if k1.Transport.Proxy.URL != k2.Transport.Proxy.URL ||
		k1.Transport.Proxy.Disable != k2.Transport.Proxy.Disable ||
		!headersEqual(k1.Transport.Proxy.Headers, k2.Transport.Proxy.Headers) {
		return false
	}

	return true
}

func fleetToReader(agentID string, headers map[string]string, logLevelOverride string, cfg *configuration.Configuration) (io.ReadSeeker, error) {
	agentConfig := map[string]interface{}{
		"id":                           agentID,
		"headers":                      headers,
		"logging.level":                cfg.Settings.LoggingConfig.Level,
		"logging.to_files":             cfg.Settings.LoggingConfig.ToFiles,
		"logging.to_stderr":            cfg.Settings.LoggingConfig.ToStderr,
		"logging.files.path":           cfg.Settings.LoggingConfig.Files.Path,
		"logging.event_data.to_files":  cfg.Settings.EventLoggingConfig.ToFiles,
		"logging.event_data.to_stderr": cfg.Settings.EventLoggingConfig.ToStderr,
		"monitoring.http":              cfg.Settings.MonitoringConfig.HTTP,
		"monitoring.pprof":             cfg.Settings.MonitoringConfig.Pprof,
	}
	if logLevelOverride != "" {
		agentConfig["logging.level_override"] = logLevelOverride
	}
	configToStore := map[string]interface{}{
		"fleet": cfg.Fleet,
		"agent": agentConfig,
	}
	data, err := yaml.Marshal(configToStore)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

type policyChange struct {
	ctx        context.Context
	log        *logger.Logger
	cfg        *config.Config
	action     fleetapi.Action
	acker      acker.Acker
	ackWatcher chan struct{}
	disableAck bool
}

func newPolicyChange(
	ctx context.Context,
	log *logger.Logger,
	config *config.Config,
	action fleetapi.Action,
	acker acker.Acker,
	makeCh bool,
	disableAck bool) *policyChange {
	var ackWatcher chan struct{}
	if makeCh {
		// we don't need it otherwise
		ackWatcher = make(chan struct{})
	}
	return &policyChange{
		ctx:        ctx,
		log:        log,
		cfg:        config,
		action:     action,
		acker:      acker,
		ackWatcher: ackWatcher,
		disableAck: disableAck,
	}
}

func (l *policyChange) Config() *config.Config {
	return l.cfg
}

// Ack is the post-apply hook called by the coordinator's ack chain.
//
// Disk persistence happens in Handle() so that the error returned by Ack
// reflects only Fleet-side ack failures, not local persistence failures (see
// https://github.com/elastic/elastic-agent/issues/13677):
//
//  1. Send the network ack (unless explicitly disabled). A failure here
//     propagates so the coordinator can retry.
//  2. Commit the ack batch. Failures propagate.
func (l *policyChange) Ack() error {
	if !l.disableAck && l.action != nil {
		if err := l.acker.Ack(l.ctx, l.action); err != nil {
			return err
		}
		if err := l.acker.Commit(l.ctx); err != nil {
			return err
		}
		if l.ackWatcher != nil {
			close(l.ackWatcher)
		}
	}

	return nil
}

// WaitAck waits for policy change to be acked.
// Policy change ack is awaitable only in case commit flag was set.
// Caller is responsible to use any reasonable deadline otherwise
// function call can be endlessly blocking.
func (l *policyChange) WaitAck(ctx context.Context) {
	if l.ackWatcher == nil {
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
