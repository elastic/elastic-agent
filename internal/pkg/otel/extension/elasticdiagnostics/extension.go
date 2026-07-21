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
	"maps"
	"net"
	"net/http"
	"runtime/pprof"
	"slices"
	"strings"
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
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

var (
	_ component.Component = (*diagnosticsExtension)(nil)

	// The elasticdiagnostics extension also implements the otelmanager.DiagnosticExtension
	// and otelmanager.ActionExtension interfaces.
	// NOTE: Changing the signature will require changes to libbeat and beatreceivers. Don't remove this.
	_ otelmanager.DiagnosticExtension = (*diagnosticsExtension)(nil)
	_ otelmanager.ActionExtension     = (*diagnosticsExtension)(nil)
)

type diagHook struct {
	description string
	filename    string
	contentType string
	hook        func() []byte
}

// actionHandler is the callback a beat receiver registers to receive Fleet
// actions routed to it. It matches the signature of management.Action.Execute.
type actionHandler func(ctx context.Context, params map[string]any) (map[string]any, error)

type diagnosticsExtension struct {
	listener net.Listener
	server   *http.Server
	logger   *zap.Logger
	logp     *logp.Logger

	diagnosticsConfig *Config
	collectorConfig   *confmap.Conf
	componentHooks    map[string][]*diagHook
	globalHooks       map[string]*diagHook

	// actionHandlers is keyed by elastic-agent component ID (e.g.
	// "osquery-default"), resolved from the OTel receiver name at
	// registration time via translate.ComponentIDFromReceiverName. The inner
	// map is keyed by the full OTel receiver name, because a single component
	// can be split across multiple receivers — one per input stream, unless
	// the component's spec sets single_receiver: true.
	// Routing an action requires exactly one receiver registered for the
	// target component; more than one is treated as ambiguous (see
	// serveAction) rather than guessing, since there is no per-stream
	// targeting information in a Fleet action today.
	actionHandlers map[string]map[string]actionHandler

	mx         sync.Mutex
	hooksMtx   sync.Mutex
	configMtx  sync.Mutex
	actionsMtx sync.Mutex
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
	mux.HandleFunc("/actions", d.serveAction)

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

// RegisterActionHandler API exposes the ability for beat receivers to register a
// handler for Fleet actions routed to them. componentName is the OTel receiver
// name (e.g. "osquerybeatreceiver/_agent-component/osquery-default/stream"). It
// returns an error if this registration makes routing for the component
// ambiguous (see ambiguousActionRoutingError); the handler is still recorded so
// that action requests keep failing loudly via resolveActionHandler, but the
// caller should log this error since it is otherwise only surfaced the next
// time Fleet dispatches an action to this component.
// NOTE: Changing the function signature will require changes to libbeat and beatreceivers. Proceed with caution.
func (d *diagnosticsExtension) RegisterActionHandler(componentName string, handler func(ctx context.Context, params map[string]any) (map[string]any, error)) error {
	compID, ok := translate.ComponentIDFromReceiverName(componentName)
	if !ok {
		return fmt.Errorf("receiver name %q does not contain the expected component prefix, ignoring registration", componentName)
	}
	d.actionsMtx.Lock()
	defer d.actionsMtx.Unlock()
	if d.actionHandlers[compID] == nil {
		d.actionHandlers[compID] = make(map[string]actionHandler)
	}
	d.actionHandlers[compID][componentName] = handler
	return ambiguityError(compID, d.actionHandlers[compID])
}

// UnregisterActionHandler removes a previously registered action handler.
// NOTE: Changing the function signature will require changes to libbeat and beatreceivers. Proceed with caution.
func (d *diagnosticsExtension) UnregisterActionHandler(componentName string) {
	compID, ok := translate.ComponentIDFromReceiverName(componentName)
	if !ok {
		return
	}
	d.actionsMtx.Lock()
	defer d.actionsMtx.Unlock()
	delete(d.actionHandlers[compID], componentName)
	if len(d.actionHandlers[compID]) == 0 {
		delete(d.actionHandlers, compID)
	}
}

// resolveActionHandler returns the sole action handler registered for
// componentID. If more than one receiver has registered a handler for this
// component (possible when a component's input runs as multiple per-stream
// receivers, see actionHandlers), routing is ambiguous: there is no
// per-stream targeting information in a Fleet action to pick the right one,
// so this returns an error naming the conflicting receivers rather than
// guessing. Components whose inputs register custom actions must set
// single_receiver: true in their spec to avoid this.
func (d *diagnosticsExtension) resolveActionHandler(componentID string) (actionHandler, error) {
	d.actionsMtx.Lock()
	defer d.actionsMtx.Unlock()
	handlers := d.actionHandlers[componentID]
	if len(handlers) == 0 {
		return nil, fmt.Errorf("no action handler registered for component %q", componentID)
	}
	if err := ambiguityError(componentID, handlers); err != nil {
		return nil, err
	}
	for _, handler := range handlers {
		return handler, nil
	}
	// Unreachable in practice: len(handlers) is checked above (0 handled,
	// >1 handled by ambiguityError), so exactly one iteration of the loop
	// above always runs.
	return nil, fmt.Errorf("no action handler registered for component %q", componentID)
}

// ambiguityError returns a non-nil error if more than one receiver has
// registered an action handler for componentID. Callers must not invoke any
// of these handlers in that case, since there is no per-stream targeting
// information in a Fleet action to pick the right one.
func ambiguityError(componentID string, handlers map[string]actionHandler) error {
	if len(handlers) <= 1 {
		return nil
	}
	receiverNames := slices.Sorted(maps.Keys(handlers))
	return fmt.Errorf("%w for component %q: %d receivers registered actions (%s); "+
		"this input must set single_receiver: true in its component spec to support actions",
		errAmbiguousActionRouting, componentID, len(receiverNames), strings.Join(receiverNames, ", "))
}

// errAmbiguousActionRouting identifies the resolveActionHandler failure mode
// where multiple receivers registered actions for the same component, so
// serveAction can map it to a distinct HTTP status from a plain "not found".
var errAmbiguousActionRouting = errors.New("ambiguous action routing")

// serveAction handles POST /actions. It resolves the action handler registered
// for the requested component ID and invokes it, returning the result (or
// error) as JSON. It always responds 200 unless the request itself is
// malformed or no handler is found for the requested component.
func (d *diagnosticsExtension) serveAction(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var actionReq ActionRequest
	if err := json.NewDecoder(req.Body).Decode(&actionReq); err != nil {
		d.writeActionError(w, http.StatusBadRequest, fmt.Sprintf("failed to decode request: %v", err))
		return
	}

	handler, err := d.resolveActionHandler(actionReq.ComponentID)
	if err != nil {
		status := http.StatusNotFound
		if errors.Is(err, errAmbiguousActionRouting) {
			status = http.StatusConflict
		}
		d.writeActionError(w, status, err.Error())
		return
	}

	result, err := handler(req.Context(), actionReq.Params)
	resp := ActionResponse{Result: result}
	if err != nil {
		resp.Error = err.Error()
	}

	b, err := json.Marshal(resp)
	if err != nil {
		d.writeActionError(w, http.StatusInternalServerError, fmt.Sprintf("failed marshaling response: %v", err))
		return
	}
	w.Header().Add("content-type", "application/json")
	if _, err := w.Write(b); err != nil {
		d.logger.Error("Failed writing response to client.", zap.Error(err))
	}
}

// writeActionError writes an ActionResponse{Error: msg} as the HTTP body with
// the given status code, avoiding hand-rolled JSON string formatting.
func (d *diagnosticsExtension) writeActionError(w http.ResponseWriter, status int, msg string) {
	w.Header().Add("content-type", "application/json")
	w.WriteHeader(status)
	b, err := json.Marshal(ActionResponse{Error: msg})
	if err != nil {
		d.logger.Error("Failed marshaling error response", zap.Error(err))
		return
	}
	if _, err := w.Write(b); err != nil {
		d.logger.Error("Failed writing response to client.", zap.Error(err))
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
