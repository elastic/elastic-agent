// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/provider/envprovider"
	"go.opentelemetry.io/collector/confmap/provider/fileprovider"
	"go.opentelemetry.io/collector/confmap/provider/httpprovider"
	"go.opentelemetry.io/collector/confmap/provider/httpsprovider"
	"go.opentelemetry.io/collector/confmap/provider/yamlprovider"
	"go.opentelemetry.io/collector/otelcol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	componentmonitoring "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/internal/pkg/otel/agentprovider"
	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// newExecutionEmbedded creates a new execution which runs the otel collector in a goroutine. A metricsPort of 0 will
// result in a random port being used.
func newExecutionEmbedded(metricsPort int) *embeddedExecution {
	return &embeddedExecution{collectorMetricsPort: metricsPort}
}

type embeddedExecution struct {
	collectorMetricsPort int
}

// startCollector starts the collector in a new goroutine.
func (r *embeddedExecution) startCollector(ctx context.Context, logger *logger.Logger, cfg *confmap.Conf, errCh chan error, statusCh chan *status.AggregateStatus) (collectorHandle, error) {
	collectorCtx, collectorCancel := context.WithCancel(ctx)
	ap := agentprovider.NewProvider(cfg)

	ctl := &ctxHandle{
		collectorDoneCh: make(chan struct{}),
		cancel:          collectorCancel,
	}

	collectorMetricsPort, err := r.getCollectorMetricsPort()
	if err != nil {
		return nil, err
	}
	extConf := map[string]any{
		"endpoint": paths.DiagnosticsExtensionSocket(),
	}
	collectorEnvMap := map[string]string{
		componentmonitoring.OtelCollectorMetricsPortEnvVarName: strconv.Itoa(collectorMetricsPort),
	}
	// NewForceExtensionConverterFactory is used to ensure that the agent_status extension is always enabled.
	// It is required for the Elastic Agent to extract the status out of the OTel collector.
	settings := otel.NewSettings(
		release.Version(), []string{ap.URI()},
		otel.WithConfigConvertorFactory(NewForceExtensionConverterFactory(AgentStatusExtensionType.String(), nil)),
		otel.WithConfigConvertorFactory(NewForceExtensionConverterFactory(elasticdiagnostics.DiagnosticsExtensionID.String(), extConf)),
		otel.WithExtensionFactory(NewAgentStatusFactory(statusCh)))
	settings.DisableGracefulShutdown = true // managed by this manager
	settings.LoggingOptions = []zap.Option{zap.WrapCore(func(zapcore.Core) zapcore.Core {
		return logger.Core() // use same zap as agent
	})}
	// we need to explicitly specify the provider list because we replace the env provider
	settings.ConfigProviderSettings.ResolverSettings.ProviderFactories = []confmap.ProviderFactory{
		fileprovider.NewFactory(),
		NewFactoryWithEnvMap(collectorEnvMap), // replace the env provider with our wrapper
		yamlprovider.NewFactory(),
		httpprovider.NewFactory(),
		httpsprovider.NewFactory(),
		ap.NewFactory(),
	}
	svc, err := otelcol.NewCollector(*settings)
	if err != nil {
		collectorCancel()
		return nil, err
	}
	go func() {
		runErr := svc.Run(collectorCtx)
		close(ctl.collectorDoneCh)
		// after the collector exits, we need to report the error and a nil status
		reportErr(ctx, errCh, runErr)
		reportCollectorStatus(ctx, statusCh, nil)
	}()
	return ctl, nil
}

// getCollectorPorts returns the metrics port used by the OTel collector. If the port set in the execution struct is 0,
// a random port is returned instead.
func (r *embeddedExecution) getCollectorMetricsPort() (metricsPort int, err error) {
	// if the port is defined (non-zero), use it
	if r.collectorMetricsPort > 0 {
		return r.collectorMetricsPort, nil
	}

	// get a random port
	ports, err := findRandomTCPPorts(1)
	if err != nil {
		return 0, err
	}
	return ports[0], nil
}

type ctxHandle struct {
	collectorDoneCh chan struct{}
	cancel          context.CancelFunc
}

// Stop stops the collector
func (s *ctxHandle) Stop(waitTime time.Duration) {
	if s.cancel == nil {
		return
	}

	s.cancel()

	select {
	case <-time.After(waitTime):
		return
	case <-s.collectorDoneCh:
	}
}

// Define a provider that wraps the env provider and returns values from a static map first, deferring to the env provider
// if the env variable doesn't exist in the map.
// This is a hacky workaround for the problem where we pass some values into the configuration through env variables,
// but SetEnv causes various confusing race conditions. Considering we're probably going to get rid of this execution
// sooner rather than later, this should be fine.
const (
	schemeName = "env"
)

type provider struct {
	envProvider confmap.Provider
	envMap      map[string]string
}

func NewFactoryWithEnvMap(envMap map[string]string) confmap.ProviderFactory {
	return confmap.NewProviderFactory(func(s confmap.ProviderSettings) confmap.Provider {
		return newProviderWithEnvMap(s, envMap)
	})
}

func newProviderWithEnvMap(ps confmap.ProviderSettings, envMap map[string]string) confmap.Provider {
	envProvider := envprovider.NewFactory().Create(ps)
	return &provider{envProvider: envProvider, envMap: envMap}
}

func (emp *provider) Retrieve(ctx context.Context, uri string, watcherFunc confmap.WatcherFunc) (*confmap.Retrieved, error) {
	if !strings.HasPrefix(uri, schemeName+":") {
		return nil, fmt.Errorf("%q uri is not supported by %q provider", uri, schemeName)
	}

	// check if we have the variable in our static map, if not go to the actual environment
	envVarName, _ := parseEnvVarURI(uri[len(schemeName)+1:])
	if val, ok := emp.envMap[envVarName]; ok {
		return confmap.NewRetrievedFromYAML([]byte(val))
	}

	return emp.envProvider.Retrieve(ctx, uri, watcherFunc)
}

func (*provider) Scheme() string {
	return schemeName
}

func (*provider) Shutdown(context.Context) error {
	return nil
}

// returns (var name, default value)
func parseEnvVarURI(uri string) (string, *string) {
	const defaultSuffix = ":-"
	name, defaultValue, hasDefault := strings.Cut(uri, defaultSuffix)
	if hasDefault {
		return name, &defaultValue
	}
	return uri, nil
}
