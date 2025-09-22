package elasticdiagnosticsextension

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime/pprof"
	"strconv"
	"sync"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configtelemetry"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/service"
	otelconf "go.opentelemetry.io/contrib/otelconf/v0.3.0"
	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	_ component.Component = &diagnosticsExtension{}
)

type diagHook struct {
	description string
	filename    string
	contentType string
	hook        func() []byte
}

type diagnosticsExtension struct {
	listener net.Listener
	server   http.Server
	logger   *zap.Logger

	diagnosticsConfig *Config
	collectorConfig   *confmap.Conf
	componentHooks    map[string][]*diagHook
	globalHooks       map[string]*diagHook

	hooksMtx sync.Mutex
	confgMtx sync.Mutex
}

type serviceConfig struct {
	Service    service.Config         `mapstructure:"service"`
	Beatconfig map[string]interface{} `mapstructure:",remain"`
}

func (d *diagnosticsExtension) Start(ctx context.Context, host component.Host) error {
	var err error
	path := d.diagnosticsConfig.Host
	if d.diagnosticsConfig.Network == "unix" {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf(
					"cannot remove existing unix socket file at location %s: %w",
					path, err,
				)
			}
		}
	}

	d.registerGlobalDiagnostics()

	d.listener, err = net.Listen(d.diagnosticsConfig.Network, path)
	if err != nil {
		return fmt.Errorf("error creating listener: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/diagnostics", d)

	d.server = http.Server{
		Handler: mux,
	}
	go func() {
		if err := d.server.Serve(d.listener); err != nil && err != http.ErrServerClosed {
			d.logger.Error("HTTP server error", zap.Error(err))
		}
	}()
	d.logger.Info("Diagnostics extension started", zap.String("address", d.listener.Addr().String()))
	return nil
}

func (d *diagnosticsExtension) registerGlobalDiagnostics() {
	d.globalHooks["collector_config"] = &diagHook{
		description: "full collector configuration",
		filename:    "edot/otel-merged.yaml",
		contentType: "application/yaml",
		hook: func() []byte {
			if d.collectorConfig == nil {
				return []byte("no active OTeL Configuration")
			}
			b, err := yaml.Marshal(d.collectorConfig.ToStringMap())
			if err != nil {
				return fmt.Appendf(nil, "error: failed to convert to yaml: %v", err)
			}
			return b
		},
	}

	d.globalHooks["collector_telemetry"] = &diagHook{
		description: "internal telemetry of the collector",
		filename:    "edot/edot-telemetry.txt",
		contentType: "text/plain",
		hook: func() []byte {
			serviceCfg := serviceConfig{}
			err := d.collectorConfig.Unmarshal(&serviceCfg)
			if err != nil {
				return fmt.Appendf(nil, "error: failed to get internal telemetry: %v", err)
			}
			if serviceCfg.Service.Telemetry.Metrics.Level == configtelemetry.LevelNone {
				return []byte("internal telemetry is disabled")
			}
			addr := extractMetricAddress(serviceCfg.Service.Telemetry.Metrics.Readers)

			resp, err := http.Get(fmt.Sprintf("http://%s/metrics", addr))
			if err != nil {
				return fmt.Appendf(nil, "error: failed to get internal telemetry: %v", err)
			}
			defer resp.Body.Close()

			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Appendf(nil, "error: failed to read response body: %v", err)
			}
			return b
		},
	}

	// return basic profiles.
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

func (d *diagnosticsExtension) Shutdown(ctx context.Context) error {
	if err := d.server.Shutdown(ctx); err != nil {
		return err
	}
	return nil
}

func (d *diagnosticsExtension) NotifyConfig(ctx context.Context, conf *confmap.Conf) error {
	d.confgMtx.Lock()
	defer d.confgMtx.Unlock()
	d.collectorConfig = conf
	return nil
}

func (d *diagnosticsExtension) RegisterDiagnosticHook(componentName string, description string, filename string, contentType string, hook func() []byte) {
	d.hooksMtx.Lock()
	defer d.hooksMtx.Unlock()
	fmt.Println(d.componentHooks, componentName, filename)
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

	b, err := json.Marshal(Response{
		GlobalDiagnostics:    globalResults,
		ComponentDiagnostics: componentResults,
	})
	if err != nil {
		w.WriteHeader(503)
		w.Header().Add("content-type", "application/json")
		fmt.Fprintf(w, "{'error':'%v'}", err)
		return
	}
	w.Header().Add("content-type", "application/json")
	w.Write(b)
}

func extractMetricAddress(readers []otelconf.MetricReader) string {
	for _, reader := range readers {
		if reader.Pull != nil &&
			reader.Pull.Exporter.Prometheus != nil &&
			reader.Pull.Exporter.Prometheus.Host != nil &&
			reader.Pull.Exporter.Prometheus.Port != nil {
			return net.JoinHostPort(*reader.Pull.Exporter.Prometheus.Host, strconv.Itoa(*reader.Pull.Exporter.Prometheus.Port))
		}
	}
	return ""
}
