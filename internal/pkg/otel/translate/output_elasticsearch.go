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

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/outputs"
	"github.com/elastic/beats/v7/libbeat/outputs/elasticsearch"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

type esToOTelOptions struct {
	elasticsearch.ElasticsearchConfig `config:",inline"`

	Index                 string `config:"index"`
	Preset                string `config:"preset"`
	RetryOnStatus         []int  `config:"retry_on_status"`
	RetryOnDocumentStatus []int  `config:"retry_on_document_status"`
}

// defaultRetryOnDocumentStatus matches Beats' retry behavior for individual
// bulk response items.
var defaultRetryOnDocumentStatus = []int{
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
}

func defaultRetryOnStatus() []int {
	// Beats retries every failed bulk request except 413, which it handles by
	// splitting the batch or dropping it when it cannot be split.
	return []int{
		// 3xx
		http.StatusMultipleChoices,   // 300
		http.StatusMovedPermanently,  // 301
		http.StatusFound,             // 302
		http.StatusSeeOther,          // 303
		http.StatusNotModified,       // 304
		http.StatusUseProxy,          // 305
		http.StatusTemporaryRedirect, // 307
		http.StatusPermanentRedirect, // 308
		// 4xx, excluding 413 (Request Entity Too Large)
		http.StatusBadRequest,                   // 400
		http.StatusUnauthorized,                 // 401
		http.StatusPaymentRequired,              // 402
		http.StatusForbidden,                    // 403
		http.StatusNotFound,                     // 404
		http.StatusMethodNotAllowed,             // 405
		http.StatusNotAcceptable,                // 406
		http.StatusProxyAuthRequired,            // 407
		http.StatusRequestTimeout,               // 408
		http.StatusConflict,                     // 409
		http.StatusGone,                         // 410
		http.StatusLengthRequired,               // 411
		http.StatusPreconditionFailed,           // 412
		http.StatusRequestURITooLong,            // 414
		http.StatusUnsupportedMediaType,         // 415
		http.StatusRequestedRangeNotSatisfiable, // 416
		http.StatusExpectationFailed,            // 417
		http.StatusTeapot,                       // 418
		http.StatusMisdirectedRequest,           // 421
		http.StatusUnprocessableEntity,          // 422
		http.StatusLocked,                       // 423
		http.StatusFailedDependency,             // 424
		http.StatusTooEarly,                     // 425
		http.StatusUpgradeRequired,              // 426
		http.StatusPreconditionRequired,         // 428
		http.StatusTooManyRequests,              // 429
		http.StatusRequestHeaderFieldsTooLarge,  // 431
		http.StatusUnavailableForLegalReasons,   // 451
		// 5xx
		http.StatusInternalServerError,           // 500
		http.StatusNotImplemented,                // 501
		http.StatusBadGateway,                    // 502
		http.StatusServiceUnavailable,            // 503
		http.StatusGatewayTimeout,                // 504
		http.StatusHTTPVersionNotSupported,       // 505
		http.StatusVariantAlsoNegotiates,         // 506
		http.StatusInsufficientStorage,           // 507
		http.StatusLoopDetected,                  // 508
		http.StatusNotExtended,                   // 510
		http.StatusNetworkAuthenticationRequired, // 511
	}
}

// maxQueueEvents is a memory limiter, not a performance tuning value.
//
// The sizing below scales with the connection count, which is hosts * workers, and the
// budget is events held in memory. Left unbounded a large host list would ask for an
// unbounded amount of memory: a 60-host output would want 384,000 resident events, on the
// order of gigabytes. This ceiling exists purely to put a roof on that.
//
// It is deliberately set well above any concurrency the presets reach on a single host
// (the throughput preset asks for 25,600), so it does not interfere with normal sizing --
// it only engages on large host lists, where it trades some connection utilisation for a
// bounded footprint. Raising it costs memory roughly linearly; at typical event sizes this
// value corresponds to on the order of a gigabyte of in-flight events.
const maxQueueEvents = 64000

var defaultOptions = esToOTelOptions{
	ElasticsearchConfig: elasticsearch.DefaultConfig(),

	Index:                 "",       // Dynamic routing is disabled if index is set
	Preset:                "custom", // default is custom if not set
	RetryOnDocumentStatus: append([]int(nil), defaultRetryOnDocumentStatus...),
	RetryOnStatus:         defaultRetryOnStatus(),
}

// ESToOTelConfig converts a Beat config into OTel elasticsearch exporter config
func ESToOTelConfig(output *config.C, _ string, logger *logp.Logger) (map[string]any, map[string]any, error) {
	escfg := defaultOptions

	// check for unsupported config
	err := checkUnsupportedConfig(output)
	if err != nil {
		return nil, nil, err
	}

	// Preset must be applied before unpacking the config because it can override output fields.
	//
	// isNamedPreset distinguishes the four performance presets (balanced/throughput/scale/latency)
	// from "custom" and no preset. Only named presets drive OTel queue sizing; for custom/none
	// the user owns every queue field and those values must not be overridden.
	var isNamedPreset bool
	var presetFloor int
	var storedPreset string
	var storedPresetConfig *config.C
	if preset, presetErr := output.String("preset", -1); presetErr == nil {
		storedPreset = preset
		isNamedPreset = preset != "" && preset != "custom"

		overriddenFields, presetConfig, applyErr := elasticsearch.ApplyPreset(preset, output)
		if applyErr != nil {
			return nil, nil, applyErr
		}
		// output now has all preset values applied (including worker count), so
		// getTotalNumConnections reads the correct connection count for sizing.
		storedPresetConfig = presetConfig

		if isNamedPreset {
			// Read the preset's queue.mem.events as the throughput floor before we
			// overwrite it with the OTel-adjusted value below.
			if floor, err2 := output.Int("queue.mem.events", -1); err2 == nil {
				presetFloor = int(floor)
			}
		}

		if len(overriddenFields) > 0 {
			logger.Warnf("Performance preset '%v' overrides user setting for field(s): %s",
				preset, strings.Join(overriddenFields, ","))
		}
	}

	// maxConns and batchSize are computed once here, after ApplyPreset has written
	// the preset's worker count and queue parameters into output.
	maxConns := getTotalNumConnections(output)
	batchSize := min(getFlushMinEvents(logger, output), getBulkMaxSize(output))

	var queueSize, numConsumers int
	if isNamedPreset {
		queueSize, numConsumers = calcNamedPresetSizing(maxConns, batchSize, presetFloor)

		// Write the OTel-adjusted queue size back into output so the subsequent
		// decode picks up the correct value.
		if err := output.SetInt("queue.mem.events", -1, int64(queueSize)); err != nil {
			return nil, nil, fmt.Errorf("failed setting queue.mem.events: %w", err)
		}

		// Build a log copy with the OTel-effective queue.mem.events. storedPresetConfig
		// is the global preset table entry; must not mutate it directly.
		logCopy := config.MustNewConfigFrom(map[string]any{})
		_ = logCopy.Merge(storedPresetConfig)
		_ = logCopy.SetInt("queue.mem.events", -1, int64(queueSize))
		logger.Infof("Applying performance preset '%v': %v", storedPreset, config.DebugString(logCopy, false))
	} else {
		if storedPresetConfig != nil {
			logger.Infof("Applying performance preset '%v': %v", storedPreset, config.DebugString(storedPresetConfig, false))
		}
		// num_consumers has no beats equivalent (users never set it) so apply the
		// same two-per-connection staging model regardless of preset.
		numConsumers = 2 * maxConns
		// queue.mem.events is user-configurable in beats and must not be overridden.
		queueSize = getQueueSize(logger, output)
		if suggested := min(2*batchSize*numConsumers, maxQueueEvents); queueSize < suggested {
			logger.Infof("queue.mem.events (%d) is below the suggested minimum for %d connection(s); consider setting queue.mem.events: %d", queueSize, maxConns, suggested)
		}
	}

	unpackedMap := make(map[string]any)
	// unpack and validate ES config
	if err := output.Unpack(&unpackedMap); err != nil {
		return nil, nil, fmt.Errorf("failed unpacking config. %w", err)
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:          &escfg,
		TagName:         "config",
		SquashTagOption: "inline",
		DecodeHook:      cfgDecodeHookFunc(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating decoder. %w", err)
	}

	err = decoder.Decode(&unpackedMap)
	if err != nil {
		return nil, nil, fmt.Errorf("failed decoding config. %w", err)
	}

	if err := escfg.Validate(); err != nil {
		return nil, nil, err
	}

	hosts, err := getURL(escfg, output)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating hosts:%w", err)
	}

	otelYAMLCfg := map[string]any{
		"endpoints": hosts, // hosts, protocol, path, port

		// max_conns_per_host is a "hard" limit on number of open connections. It was added
		// because an upstream bug let the exporter spin up as many sending goroutines as it
		// liked, and the batcher implementation has a history of such changes.
		//
		// It is now load-bearing for a second reason: num_consumers is deliberately set
		// above it (see the sizing above), so this is what actually bounds the connection
		// count. Removing it would let the extra consumers open extra connections and
		// change Elasticsearch-side load, which the sizing above is specifically written
		// to avoid.
		"max_conns_per_host": maxConns, // num_workers * len(hosts) if loadbalance is true

		"sending_queue": map[string]any{
			"batch": map[string]any{
				"flush_timeout": getFlushTimeout(logger, output),
				"max_size":      escfg.BulkMaxSize, // bulk_max_size
				"min_size":      batchSize,         // queue.mem.flush.min_events, capped at max_size
				"sizer":         "items",
			},
			"enabled":           true,
			"queue_size":        queueSize,
			"block_on_overflow": true,
			"wait_for_result":   true,
			"num_consumers":     numConsumers, // two per connection
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

	// timeout is enforced by the ES exporter via timeoutInterceptor, which wraps each request
	// context with context.WithTimeout. beatsauthextension exposes only the beats http.Client's
	// Transport (not the client itself), so http.Client.Timeout is never applied — the exporter
	// must carry this value. The beats default is 90s and this should never be zero; a zero value
	// passed to timeoutInterceptor immediately cancels every request (upstream fix tracked at
	// https://github.com/open-telemetry/opentelemetry-collector/issues/15677).
	if escfg.Transport.Timeout > 0 {
		otelYAMLCfg["timeout"] = escfg.Transport.Timeout
	}

	// ssl block, idle_connection_timeout, proxy_url, proxy_headers, and proxy_disable
	// are handled by beatsauthextension https://github.com/elastic/opentelemetry-collector-components/tree/main/extension/beatsauthextension
	// caller of this method should take care of integrating the extension

	return otelYAMLCfg, nil, nil
}

// calcNamedPresetSizing computes the OTel queue size and consumer count for a
// named performance preset (balanced/throughput/scale/latency).
//
// maxConns is the total connection count (hosts × workers) after the preset has
// been applied. batchSize is queue.mem.flush.min_events capped at bulk_max_size.
// floor is the preset's own queue.mem.events value — the throughput minimum the
// user implicitly accepted by choosing that preset, which we never go below.
func calcNamedPresetSizing(maxConns, batchSize, floor int) (queueSize, numConsumers int) {
	if batchSize <= 0 {
		// Presets always set a positive batch size; guard against zero to avoid
		// divide-by-zero if config parsing somehow yields an empty value.
		batchSize = 1
	}
	// Two consumers per connection: one sends while the other stages the next
	// batch, keeping each connection continuously fed without stalling.
	numConsumers = 2 * maxConns
	// Two batches per consumer in the queue at any moment so no consumer ever
	// stalls waiting for the queue to produce the next batch.
	queueSize = 2 * batchSize * numConsumers
	if queueSize > maxQueueEvents {
		// Large host lists would otherwise demand unbounded in-flight events.
		// Scale back proportionally: halving numConsumers also halves connections,
		// keeping the queue-to-batch ratio constant at the memory ceiling.
		queueSize = maxQueueEvents
		numConsumers = max(1, queueSize/(2*batchSize))
		// A future preset whose queue.mem.events exceeds the ceiling would leave
		// numConsumers clamped to the ceiling value; honour the floor here too
		// and scale numConsumers proportionally from the larger queue size.
		if floor > queueSize {
			queueSize = floor
			numConsumers = max(1, queueSize/(2*batchSize))
		}
	} else if floor > queueSize {
		// The floor is above the formula result but below the memory ceiling.
		// Only the queue size needs to grow; numConsumers stays at 2*maxConns
		// because the cap path has not changed it from the connection-model value.
		queueSize = floor
	}
	return queueSize, numConsumers
}

// getTotalNumConnections returns the number of connections that beats would
// have used taking into account hosts, loadbalance and worker
func getTotalNumConnections(cfg *config.C) int {
	hostList, err := outputs.ReadHostList(cfg)
	if err != nil {
		return 1
	}
	return len(hostList)
}

func getRetryConfig(escfg esToOTelOptions) map[string]any {
	// Retries
	retryCfg := map[string]any{
		"enabled":                  true,
		"max_retries":              escfg.MaxRetries,
		"initial_interval":         escfg.Backoff.Init, // backoff.init
		"max_interval":             escfg.Backoff.Max,  // backoff.max
		"retry_on_status":          escfg.RetryOnStatus,
		"retry_on_document_status": escfg.RetryOnDocumentStatus,
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
