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
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/common/transport/kerberos"
	"github.com/elastic/beats/v7/libbeat/outputs"
	"github.com/elastic/beats/v7/libbeat/outputs/elasticsearch"
	"github.com/elastic/beats/v7/libbeat/publisher/queue/memqueue"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
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

// ToOTelConfig converts a Beat config into OTel elasticsearch exporter config
// Ensure cloudid is handled before calling this method
// Note: This method may override output queue settings defined by user.
func ToOTelConfig(output *config.C, logger *logp.Logger) (map[string]any, error) {
	escfg := defaultOptions

	// check for unsupported config
	err := checkUnsupportedConfig(output)
	if err != nil {
		return nil, err
	}

	// apply preset here
	// It is important to apply preset before unpacking the config, as preset can override output fields
	preset, err := output.String("preset", -1)
	if err == nil {
		// Performance preset is present, apply it and log any fields that
		// were overridden
		overriddenFields, presetConfig, err := elasticsearch.ApplyPreset(preset, output)
		if err != nil {
			return nil, err
		}
		logger.Infof("Applying performance preset '%v': %v",
			preset, config.DebugString(presetConfig, false))
		logger.Warnf("Performance preset '%v' overrides user setting for field(s): %s",
			preset, strings.Join(overriddenFields, ","))
	}

	unpackedMap := make(map[string]any)
	// unpack and validate ES config
	if err := output.Unpack(&unpackedMap); err != nil {
		return nil, fmt.Errorf("failed unpacking config. %w", err)
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:          &escfg,
		TagName:         "config",
		SquashTagOption: "inline",
		DecodeHook:      cfgDecodeHookFunc(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed creating decoder. %w", err)
	}

	err = decoder.Decode(&unpackedMap)
	if err != nil {
		return nil, fmt.Errorf("failed decoding config. %w", err)
	}

	if err := escfg.Validate(); err != nil {
		return nil, err
	}

	hosts, err := getURL(escfg, output)
	if err != nil {
		return nil, fmt.Errorf("error creating hosts:%w", err)
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
				"flush_timeout": "10s",
				"max_size":      escfg.BulkMaxSize, // bulk_max_size
				"min_size":      0,                 // 0 means immediately trigger a flush
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
	}
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
	otelYAMLCfg["retry"] = retryCfg

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
	// proxy_url, proxy_headers, proxy_disable are handled by beatsauthextension https://github.com/elastic/opentelemetry-collector-components/tree/main/extension/beatsauthextension
	// caller of this method should take care of integrating the extension

	return otelYAMLCfg, nil
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
		var params = make(map[string][]string, 0)
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

// log warning for unsupported config
func checkUnsupportedConfig(cfg *config.C) error {
	if cfg.HasField("indices") {
		return fmt.Errorf("indices is currently not supported: %w", errors.ErrUnsupported)
	} else if value, err := cfg.Bool("allow_older_versions", -1); err == nil && !value {
		return fmt.Errorf("allow_older_versions:false is currently not supported: %w", errors.ErrUnsupported)
	} else if value, err := cfg.Bool("loadbalance", -1); err == nil && !value {
		return fmt.Errorf("ladbalance:false is currently not supported: %w", errors.ErrUnsupported)
	} else if cfg.HasField("non_indexable_policy") {
		return fmt.Errorf("non_indexable_policy is currently not supported: %w", errors.ErrUnsupported)
	} else if val, err := cfg.Int("max_retries", -1); err == nil && val < 0 {
		return fmt.Errorf("max_retries should be non-negative: %w", errors.ErrUnsupported)
	}

	return nil
}

// Helper function to check if a struct is empty
func isStructEmpty(s any) bool {
	return reflect.DeepEqual(s, reflect.Zero(reflect.TypeOf(s)).Interface())
}

// Helper function to conditionally add fields to the map
func setIfNotNil(m map[string]any, key string, value any) {
	if value == nil {
		return
	}

	v := reflect.ValueOf(value)

	switch v.Kind() {
	case reflect.String:
		if v.String() != "" {
			m[key] = value
		}
	case reflect.Map, reflect.Slice:
		if v.Len() > 0 {
			m[key] = value
		}
	case reflect.Struct:
		if !isStructEmpty(value) {
			m[key] = value
		}
	default:
		m[key] = value
	}
}

func getQueueSize(logger *logp.Logger, output *config.C) int {
	size, err := output.Int("queue.mem.events", -1)
	if err != nil {
		logger.Debugf("Failed to get queue size: %v", err)
		return memqueue.DefaultEvents // return default queue.mem.events for sending_queue in case of an errr
	}
	return int(size)
}

func cfgDecodeHookFunc() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data any,
	) (any, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}

		switch {
		case t == reflect.TypeOf(time.Duration(5)):
			d, err := time.ParseDuration(data.(string))
			if err != nil {
				return d, fmt.Errorf("failed parsing duration: %w", err)
			} else {
				return d, nil
			}
		case t == reflect.TypeOf(tlscommon.TLSVerificationMode(0)):
			verificationMode := tlscommon.TLSVerificationMode(0)
			if err := verificationMode.Unpack(data); err != nil {
				return nil, fmt.Errorf("failed parsing TLS verification mode: %w", err)
			}
			return verificationMode, nil
		case t == reflect.TypeOf(httpcommon.ProxyURI(url.URL{})):
			proxyURL := httpcommon.ProxyURI(url.URL{})
			if err := proxyURL.Unpack(data.(string)); err != nil {
				return nil, fmt.Errorf("failed parsing proxy_url: %w", err)
			}
			return proxyURL, nil
		case t == reflect.TypeOf(kerberos.AuthType(0)):
			var authType kerberos.AuthType
			if err := authType.Unpack(data.(string)); err != nil {
				return nil, fmt.Errorf("failed parsing kerberos.auth_type: %w", err)
			}
			return authType, nil
		case t == reflect.TypeOf([]string{}):
			return []string{data.(string)}, nil
		case t == reflect.TypeOf([]tlscommon.CipherSuite{tlscommon.CipherSuite(0)}):
			cipherSuite := tlscommon.CipherSuite(0)
			if err := cipherSuite.Unpack(data); err != nil {
				return nil, fmt.Errorf("failed parsing ssl cipher_suites: %w", err)
			}
			return []tlscommon.CipherSuite{cipherSuite}, nil
		case t == reflect.TypeOf([]tlscommon.TLSVersion{tlscommon.TLSVersion(0)}):
			tlsVersion := tlscommon.TLSVersion(0)
			if err := tlsVersion.Unpack(data); err != nil {
				return nil, fmt.Errorf("failed parsing ssl supported_protocols: %w", err)
			}
			return []tlscommon.TLSVersion{tlsVersion}, nil
		case t == reflect.TypeOf([]tlscommon.TLSCurveType{tlscommon.TLSCurveType(0)}):
			tlsCurveType := tlscommon.TLSCurveType(0)
			if err := tlsCurveType.Unpack(data); err != nil {
				return nil, fmt.Errorf("failed parsing ssl curve_types: %w", err)
			}
			return []tlscommon.TLSCurveType{tlsCurveType}, nil
		default:
			return data, nil
		}
	}
}
