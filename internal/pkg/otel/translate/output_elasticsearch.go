// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	otelcomponent "go.opentelemetry.io/collector/component"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/outputs"
	"github.com/elastic/beats/v7/libbeat/outputs/elasticsearch"
	"github.com/elastic/beats/v7/x-pack/otel/extension/beatsauthextension"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

type esToOTelOptions struct {
	elasticsearch.ElasticsearchConfig `config:",inline"`

	Index         string `config:"index"`
	Preset        string `config:"preset"`
	RetryOnStatus []int  `config:"retry_on_status"`
}

var defaultOptions = esToOTelOptions{
	ElasticsearchConfig: elasticsearch.DefaultConfig(),

	Index:  "",       // Dynamic routing is disabled if index is set
	Preset: "custom", // default is custom if not set
	RetryOnStatus: []int{
		// 429
		http.StatusTooManyRequests,
		// 5xx
		http.StatusInternalServerError,
		http.StatusNotImplemented,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
		http.StatusHTTPVersionNotSupported,
		http.StatusVariantAlsoNegotiates,
		http.StatusInsufficientStorage,
		http.StatusLoopDetected,
		http.StatusNotExtended,
		http.StatusNetworkAuthenticationRequired,
	},
}

// ESToOTelConfig converts a Beat config into OTel elasticsearch exporter config
// Note: This method may override output queue settings defined by user.
func ESToOTelConfig(output *config.C, outputName string, logger *logp.Logger) (exporterCfg map[string]any, processorCfg map[string]any, extensionCfg map[string]any, err error) {
	escfg := defaultOptions

	// check for unsupported config
	err = checkUnsupportedConfig(output)
	if err != nil {
		return nil, nil, nil, err
	}

	// apply preset here
	// It is important to apply preset before unpacking the config, as preset can override output fields
	preset, err := output.String("preset", -1)
	if err == nil {
		// Performance preset is present, apply it and log any fields that
		// were overridden
		overriddenFields, presetConfig, err := elasticsearch.ApplyPreset(preset, output)
		if err != nil {
			return nil, nil, nil, err
		}
		logger.Infof("Applying performance preset '%v': %v",
			preset, config.DebugString(presetConfig, false))
		logger.Warnf("Performance preset '%v' overrides user setting for field(s): %s",
			preset, strings.Join(overriddenFields, ","))
	}

	unpackedMap := make(map[string]any)
	// unpack and validate ES config
	if err := output.Unpack(&unpackedMap); err != nil {
		return nil, nil, nil, fmt.Errorf("failed unpacking config. %w", err)
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:          &escfg,
		TagName:         "config",
		SquashTagOption: "inline",
		DecodeHook:      cfgDecodeHookFunc(),
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed creating decoder. %w", err)
	}

	err = decoder.Decode(&unpackedMap)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed decoding config. %w", err)
	}

	if err := escfg.Validate(); err != nil {
		return nil, nil, nil, err
	}

	hosts, err := getURL(escfg, output)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating hosts:%w", err)
	}

	otelYAMLCfg := map[string]any{
		"endpoints": hosts, // hosts, protocol, path, port

		// max_conns_per_host is a "hard" limit on number of open connections.
		// Ideally, escfg.NumWorkers() should map to num_consumer, but we had a bug in upstream
		// where it could spin as many goroutines as it liked.
		// Given that batcher implementation can change and it has a history of such changes,
		// let's keep max_conns_per_host setting for now and remove it once exporterhelper is stable.
		"max_conns_per_host": getTotalNumWorkers(output), // num_workers * len(hosts) if loadbalance is true

		"sending_queue": map[string]any{
			"batch": map[string]any{
				"flush_timeout": getFlushTimeout(logger, output),
				"max_size":      escfg.BulkMaxSize,                                         // bulk_max_size
				"min_size":      min(getFlushMinEvents(logger, output), escfg.BulkMaxSize), // queue.mem.flush.min_events, capped at max_size
				"sizer":         "items",
			},
			"enabled":           true,
			"queue_size":        getQueueSize(logger, output),
			"block_on_overflow": true,
			"wait_for_result":   true,
			"num_consumers":     getTotalNumWorkers(output), // num_workers * len(hosts) if loadbalance is true
		},

		"logs_dynamic_pipeline": map[string]any{
			"enabled": true,
		},
		"logs_dynamic_id":           map[string]any{"enabled": true},
		"include_source_on_error":   true,
		"retry":                     getRetryConfig(escfg),
		"suppress_conflict_errors":  true,
		"bulk_response_filter_path": "errors,items.*.error,items.*.status,items.*.failure_store",
	}

	// Compression
	otelYAMLCfg["compression"] = "none"
	if escfg.CompressionLevel > 0 {
		otelYAMLCfg["compression"] = "gzip"
		otelYAMLCfg["compression_params"] = map[string]any{
			"level": escfg.CompressionLevel,
		}
	}

	// Authentication
	setIfNotNil(otelYAMLCfg, "user", escfg.Username)                                             // username
	setIfNotNil(otelYAMLCfg, "password", escfg.Password)                                         // password
	setIfNotNil(otelYAMLCfg, "api_key", base64.StdEncoding.EncodeToString([]byte(escfg.APIKey))) // api_key

	setIfNotNil(otelYAMLCfg, "headers", escfg.Headers) // headers
	// Dynamic routing is disabled if output.elasticsearch.index is set
	setIfNotNil(otelYAMLCfg, "logs_index", escfg.Index) // index

	// idle_connection_timeout, timeout, ssl block,
	// proxy_url, proxy_headers, proxy_disable are handled by beatsauthextension
	extensionID := getBeatsAuthExtensionID(outputName)
	extensionConfig, err := getBeatsAuthExtensionConfig(output)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error supporting http parameters for output: %s, error: %w", outputName, err)
	}

	// sets extensionCfg
	extensionCfg = map[string]any{
		extensionID.String(): extensionConfig,
	}

	// add authenticator to ES config
	otelYAMLCfg["auth"] = map[string]any{
		"authenticator": extensionID.String(),
	}

	return otelYAMLCfg, nil, extensionCfg, nil
}

// getTotalNumWorkers returns the number of hosts that beats would
// have used taking into account hosts, loadbalance and worker
func getTotalNumWorkers(cfg *config.C) int {
	hostList, err := outputs.ReadHostList(cfg)
	if err != nil {
		return 1
	}
	return len(hostList)
}

func getRetryConfig(escfg esToOTelOptions) map[string]any {
	// Retries
	retryCfg := map[string]any{
		"enabled":          true,
		"max_retries":      escfg.MaxRetries,
		"initial_interval": escfg.Backoff.Init, // backoff.init
		"max_interval":     escfg.Backoff.Max,  // backoff.max
		"retry_on_status":  escfg.RetryOnStatus,
	}

	if escfg.MaxRetries == 0 {
		// Disable retries
		retryCfg = map[string]any{
			"enabled": false,
		}
	}
	return retryCfg
}

func getURL(escfg esToOTelOptions, output *config.C) ([]string, error) {
	// Create url using host name, protocol and path
	outputHosts, err := outputs.ReadHostList(output)
	if err != nil {
		return nil, fmt.Errorf("error reading host list: %w", err)
	}

	hosts := []string{}
	for _, h := range outputHosts {
		esURL, err := common.MakeURL(escfg.Protocol, escfg.Path, h, 9200)
		if err != nil {
			return nil, fmt.Errorf("cannot generate ES URL from host %w", err)
		}
		if !slices.Contains(hosts, esURL) {
			hosts = append(hosts, esURL)
		}
	}

	if len(escfg.Params) != 0 {
		// convert params to map[string][]string
		params := make(map[string][]string, 0)
		for key, value := range escfg.Params {
			params[key] = []string{value}
		}

		decodedParam := url.Values(params)
		// It is enough to add params as encoded query to any one host
		// Elasticsearch exporter will make sure to add these for every outgoing request
		for i := range hosts {
			hosts[i] = strings.Join([]string{hosts[0], decodedParam.Encode()}, "?")
		}
	}

	return hosts, nil
}

// getBeatsAuthExtensionID returns the id for beatsauth extension
// outputName here is name of the output defined in elastic-agent.yml. For ex: default, monitoring
func getBeatsAuthExtensionID(outputName string) otelcomponent.ID {
	extensionName := fmt.Sprintf("%s%s", OtelNamePrefix, outputName)
	return otelcomponent.NewIDWithName(otelcomponent.MustNewType(BeatsAuthExtensionType), extensionName)
}

// getBeatsAuthExtensionConfig sets http transport settings on beatsauth
// this is only required for elasticsearch output
func getBeatsAuthExtensionConfig(outputCfg *config.C) (map[string]any, error) {
	authSettings := beatsauthextension.BeatsAuthConfig{
		Transport: elasticsearch.ESDefaultTransportSettings(),
	}

	if err := outputCfg.Unpack(&authSettings); err != nil {
		return nil, err
	}

	newConfig, err := config.NewConfigFrom(authSettings)
	if err != nil {
		return nil, err
	}

	// proxy_url on newConfig is of type url.URL. Beatsauth extension expects it to be of string type instead
	// this logic here converts url.URL to string type similar to what a user would set on filebeat config
	if authSettings.Transport.Proxy.URL != nil {
		err = newConfig.SetString("proxy_url", -1, authSettings.Transport.Proxy.URL.String())
		if err != nil {
			return nil, fmt.Errorf("error settingg proxy url:%w ", err)
		}
	}

	if authSettings.Kerberos != nil {
		err = newConfig.SetString("kerberos.auth_type", -1, authSettings.Kerberos.AuthType.String())
		if err != nil {
			return nil, fmt.Errorf("error setting kerberos auth type url:%w ", err)
		}
	}

	var newMap map[string]any
	err = newConfig.Unpack(&newMap)
	if err != nil {
		return nil, err
	}

	// required to make the extension not cause the collector to fail and exit on startup
	newMap["continue_on_error"] = true

	return newMap, nil
}

// log warning for unsupported config
func checkUnsupportedConfig(cfg *config.C) error {
	if cfg.HasField("indices") {
		return fmt.Errorf("indices is currently not supported: %w", errors.ErrUnsupported)
	} else if value, err := cfg.Bool("allow_older_versions", -1); err == nil && !value {
		return fmt.Errorf("allow_older_versions:false is currently not supported: %w", errors.ErrUnsupported)
	} else if value, err := cfg.Bool("loadbalance", -1); err == nil && !value {
		return fmt.Errorf("loadbalance:false is currently not supported: %w", errors.ErrUnsupported)
	} else if cfg.HasField("non_indexable_policy") {
		return fmt.Errorf("non_indexable_policy is currently not supported: %w", errors.ErrUnsupported)
	} else if val, err := cfg.Int("max_retries", -1); err == nil && val < 0 {
		return fmt.Errorf("max_retries should be non-negative: %w", errors.ErrUnsupported)
	}

	return nil
}
