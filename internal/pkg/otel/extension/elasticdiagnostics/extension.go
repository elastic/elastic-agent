// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticdiagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime/pprof"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/extension/extensioncapabilities"
	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/elastic/beats/v7/pkg/logp"
	"github.com/elastic/beats/v7/x-pack/otel/otelmanager"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

var (
	_ component.Component = (*diagnosticsExtension)(nil)

	// The collector notifies the extension of its effective configuration
	// through this interface, which is stored to be included in diagnostics.
	_ extensioncapabilities.ConfigSnapshotWatcher = (*diagnosticsExtension)(nil)

	// The elasticdiagnostics extension also implements the otelmanager.DiagnosticExtension interface.
	// NOTE: Changing the signature will require changes to libbeat and beatreceivers. Don't remove this.
	_ otelmanager.DiagnosticExtension = (*diagnosticsExtension)(nil)
<<<<<<< HEAD
=======
	_ otelmanager.ActionExtension     = (*diagnosticsExtension)(nil)
	// The collector reports a status change for every component it starts and
	// stops; the extension uses it to drop the hooks of stopped components.
	_ componentstatus.Watcher = (*diagnosticsExtension)(nil)
>>>>>>> 599d811 (Drop diagnostic hooks for stopped otel components (#18033))
)

type diagHook struct {
	description string
	filename    string
	contentType string
	hook        func() []byte
}

type diagnosticsExtension struct {
	listener net.Listener
	server   *http.Server
	logger   *zap.Logger
	logp     *logp.Logger

	diagnosticsConfig *Config
	collectorConfig   *confmap.Conf
	componentHooks    map[string][]*diagHook
	globalHooks       map[string]*diagHook

	mx        sync.Mutex
	hooksMtx  sync.Mutex
	configMtx sync.Mutex
}

func (d *diagnosticsExtension) Start(ctx context.Context, host component.Host) error {
	d.mx.Lock()
	defer d.mx.Unlock()
	var err error

	d.logp, err = logp.NewZapLogger(d.logger)
	if err != nil {
		// NewZapLogger always returns nil error, so this shouldn't happen.
		return fmt.Errorf("failed to create logp.Logger from zap logger: %w", err)
	}

	d.registerGlobalDiagnostics()

	d.listener, err = ipc.CreateListener(d.logp, d.diagnosticsConfig.Endpoint)
	if err != nil {
		return fmt.Errorf("error creating listener: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/diagnostics", d)

	d.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		if err := d.server.Serve(d.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.logger.Error("HTTP server error", zap.Error(err))
		}
	}()
	d.logger.Info("Diagnostics extension started", zap.String("address", d.listener.Addr().String()))
	return nil
}

func (d *diagnosticsExtension) Shutdown(ctx context.Context) error {
	d.mx.Lock()
	defer d.mx.Unlock()
	if d.server == nil {
		return nil
	}
	if err := d.server.Shutdown(ctx); err != nil {
		return err
	}
	ipc.CleanupListener(d.logp, d.diagnosticsConfig.Endpoint)
	return nil
}

func (d *diagnosticsExtension) registerGlobalDiagnostics() {
	d.globalHooks["collector_config"] = &diagHook{
		description: "full collector configuration",
		filename:    "edot/otel-merged-actual.yaml",
		contentType: "application/yaml",
		hook: func() []byte {
			d.configMtx.Lock()
			defer d.configMtx.Unlock()
			if d.collectorConfig == nil {
				return []byte("no active OTel Configuration")
			}
			b, err := yaml.Marshal(d.collectorConfig.ToStringMap())
			if err != nil {
				return fmt.Appendf(nil, "error: failed to convert to yaml: %v", err)
			}
			return b
		},
	}

	d.globalHooks["environment"] = &diagHook{
		description: "environment variables of the collector process",
		filename:    "edot/environment.yaml",
		contentType: "application/yaml",
		hook: func() []byte {
			redacted, err := diagnostics.RedactEnv()
			if err != nil {
				return fmt.Appendf(nil, "error: %v", err)
			}
			b, err := yaml.Marshal(redacted)
			if err != nil {
				return fmt.Appendf(nil, "error: failed to convert to yaml: %v", err)
			}
			return b
		},
	}

	// register basic profiles.
	for _, profile := range []string{"goroutine", "heap", "allocs", "mutex", "threadcreate", "block"} {
		d.globalHooks[profile] = &diagHook{
			description: fmt.Sprintf("%s profile of the collector", profile),
			filename:    fmt.Sprintf("edot/%s.profile.gz", profile),
			contentType: "application/octet-stream",
			hook: func() []byte {
				var buf bytes.Buffer
				err := pprof.Lookup(profile).WriteTo(&buf, 0)
				if err != nil {
					return fmt.Appendf(nil, "error: failed to get %s profile: %v", profile, err)
				}
				return buf.Bytes()
			},
		}
	}
}

// NotifyConfigSnapshot implements extensioncapabilities.ConfigSnapshotWatcher.
// It stores the collector's effective configuration so it can be included in
// diagnostics as edot/otel-merged-actual.yaml.
func (d *diagnosticsExtension) NotifyConfigSnapshot(_ context.Context, snapshot extensioncapabilities.ConfigSnapshot) error {
	d.configMtx.Lock()
	defer d.configMtx.Unlock()
	if snapshot == nil {
		d.collectorConfig = nil
		return nil
	}
	d.collectorConfig = snapshot.Effective()
	return nil
}

// RegisterDiagnosticHook API exposes the ability for beat receivers to register their hooks.
// A hook registered again for the same component and filename replaces the earlier one.
// NOTE: Changing the function signature will require changes to libbeat and beatreceivers. Proceed with caution.
func (d *diagnosticsExtension) RegisterDiagnosticHook(componentName string, description string, filename string, contentType string, hook func() []byte) {
	d.hooksMtx.Lock()
	defer d.hooksMtx.Unlock()
	h := &diagHook{
		description: description,
		filename:    filename,
		contentType: contentType,
		hook:        hook,
	}
	hooks := d.componentHooks[componentName]
	if i := slices.IndexFunc(hooks, func(e *diagHook) bool { return e.filename == filename }); i >= 0 {
		hooks[i] = h
		return
	}
	d.componentHooks[componentName] = append(hooks, h)
}

// ComponentStatusChanged implements componentstatus.Watcher. It drops the
// diagnostic hooks of a component once that component has stopped, so a
// receiver torn down by a config reload is no longer referenced by the
// extension and no longer contributes files to a diagnostics bundle.
//
// Hooks are keyed by the OTel component ID the receiver registers under
// (beat.Info.ComponentID, which is the receiver's own component.ID), so it
// matches the status source here. The collector reports StatusStopped after
// the component's Shutdown returns, so nothing can register a hook for this
// generation of the component afterwards.
func (d *diagnosticsExtension) ComponentStatusChanged(source *componentstatus.InstanceID, event *componentstatus.Event) {
	if source == nil || event == nil || event.Status() != componentstatus.StatusStopped {
		return
	}
	componentName := source.ComponentID().String()
	d.hooksMtx.Lock()
	_, had := d.componentHooks[componentName]
	delete(d.componentHooks, componentName)
	d.hooksMtx.Unlock()
	if had {
		d.logger.Debug("removed diagnostic hooks of stopped component",
			zap.String("otelcol.component.id", componentName))
	}
}

func (d *diagnosticsExtension) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	componentResults, globalResults := d.runHooks()

	// only add a CPU profile if requested via query parameter.
	if req.URL.Query().Get("cpu") == "true" {
		diagCPUDuration := diagnostics.DiagCPUDuration

		// check if cpuduration parameter is set, if so override the default duration
		// if parsing fails, log the error and use the default duration
		if req.URL.Query().Get("cpuduration") != "" {
			var err error
			diagCPUDuration, err = time.ParseDuration(req.URL.Query().Get("cpuduration"))
			if err != nil {
				d.logger.Error("Failed parsing cpuduration parameter, using default", zap.String("cpuduration", req.URL.Query().Get("cpuduration")), zap.Error(err))
				diagCPUDuration = diagnostics.DiagCPUDuration
			}
		}
		cpuProfile, err := diagnostics.CreateCPUProfile(req.Context(), diagCPUDuration)
		if err != nil {
			d.logger.Error("Failed creating CPU profile", zap.Error(err))
		}
		globalResults = append(globalResults, &proto.ActionDiagnosticUnitResult{
			Name:        "cpu",
			Filename:    "edot/cpu.profile.gz",
			ContentType: "application/octet-stream",
			Description: "CPU profile of the collector",
			Content:     cpuProfile,
		})
	}

	b, err := json.Marshal(Response{
		GlobalDiagnostics:    globalResults,
		ComponentDiagnostics: componentResults,
	})
	w.Header().Add("content-type", "application/json")
	if err != nil {
		d.logger.Error("Failed marshaling response", zap.Error(err))
		w.WriteHeader(500)
		if _, err := fmt.Fprintf(w, "{'error':'%v'}", err); err != nil {
			d.logger.Error("Failed writing response to client.", zap.Error(err))
		}
		return
	}
	if _, err := w.Write(b); err != nil {
		d.logger.Error("Failed writing response to client.", zap.Error(err))
	}
}

// runHooks runs the hooks without holding hooksMtx, so a slow hook doesn't
// block receivers that register or unregister hooks.
func (d *diagnosticsExtension) runHooks() ([]*proto.ActionDiagnosticUnitResult, []*proto.ActionDiagnosticUnitResult) {
	d.hooksMtx.Lock()
	componentHooks := make(map[string][]*diagHook, len(d.componentHooks))
	for name, hooks := range d.componentHooks {
		componentHooks[name] = slices.Clone(hooks)
	}
	d.hooksMtx.Unlock()

	componentResults := make([]*proto.ActionDiagnosticUnitResult, 0)
	for name, hooks := range componentHooks {
		for _, hook := range hooks {
			componentResults = append(componentResults, hook.result(name))
		}
	}

	globalResults := make([]*proto.ActionDiagnosticUnitResult, 0)
	for name, hook := range d.globalHooks {
		globalResults = append(globalResults, hook.result(name))
	}
	return componentResults, globalResults
}

func (h *diagHook) result(name string) *proto.ActionDiagnosticUnitResult {
	return &proto.ActionDiagnosticUnitResult{
		Name:        name,
		Filename:    h.filename,
		ContentType: h.contentType,
		Description: h.description,
		Content:     h.hook(),
		Generated:   timestamppb.Now(),
	}
}
