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
	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/elastic/beats/v7/x-pack/otel/otelmanager"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/diagnostics"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

var (
	_ component.Component = (*diagnosticsExtension)(nil)

	// The elasticdiagnostics extension also implements the otelmanager.DiagnosticExtension interface.
	// NOTE: Changing the signature will require changes to libbeat and beatreceivers. Don't remove this.
	_ otelmanager.DiagnosticExtension = (*diagnosticsExtension)(nil)
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

func (d *diagnosticsExtension) NotifyConfig(ctx context.Context, conf *confmap.Conf) error {
	d.configMtx.Lock()
	defer d.configMtx.Unlock()
	d.collectorConfig = conf
	return nil
}

// RegisterDiagnosticHook API exposes the ability for beat receivers to register their hooks.
// NOTE: Changing the function signature will require changes to libbeat and beatreceivers. Proceed with caution.
func (d *diagnosticsExtension) RegisterDiagnosticHook(componentName string, description string, filename string, contentType string, hook func() []byte) {
	d.hooksMtx.Lock()
	defer d.hooksMtx.Unlock()
	if _, ok := d.componentHooks[componentName]; ok {
		d.componentHooks[componentName] = append(d.componentHooks[componentName], &diagHook{
			description: description,
			filename:    filename,
			contentType: contentType,
			hook:        hook,
		})
	} else {
		d.componentHooks[componentName] = []*diagHook{
			{
				description: description,
				filename:    filename,
				contentType: contentType,
				hook:        hook,
			},
		}
	}
}

func (d *diagnosticsExtension) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	d.hooksMtx.Lock()
	defer d.hooksMtx.Unlock()
	componentResults := make([]*proto.ActionDiagnosticUnitResult, 0)
	for name, hooks := range d.componentHooks {
		for _, hook := range hooks {
			componentResults = append(componentResults, &proto.ActionDiagnosticUnitResult{
				Name:        name,
				Filename:    hook.filename,
				ContentType: hook.contentType,
				Description: hook.description,
				Content:     hook.hook(),
				Generated:   timestamppb.Now(),
			})
		}
	}

	globalResults := make([]*proto.ActionDiagnosticUnitResult, 0)
	for name, hook := range d.globalHooks {
		globalResults = append(globalResults, &proto.ActionDiagnosticUnitResult{
			Name:        name,
			Filename:    hook.filename,
			ContentType: hook.contentType,
			Description: hook.description,
			Content:     hook.hook(),
			Generated:   timestamppb.Now(),
		})
	}

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
