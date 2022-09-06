// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetes

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/elastic/elastic-agent-autodiscover/utils"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

const (
	integration = "package"
	datastreams = "data_streams"

	host        = "host"
	period      = "period"
	timeout     = "timeout"
	metricspath = "metrics_path"
	username    = "username"
	password    = "password"

	// Just placeholders, not supported yet.
	namespace      = "namespace"
	ssl            = "ssl"
	metricsfilters = "metrics_filters"

	defaultTimeout = "3s"
	defaultPeriod  = "1m"
)

type hintsBuilder struct {
	Key string

	logger *logp.Logger
}

func (m *hintsBuilder) getIntegration(hints mapstr.M) string {
	return utils.GetHintString(hints, m.Key, integration)
}

func (m *hintsBuilder) getDataStreams(hints mapstr.M) []string {
	var ds []string
	ds = utils.GetHintAsList(hints, m.Key, datastreams)

	return ds
}

func (m *hintsBuilder) getHost(hints mapstr.M) string {
	return utils.GetHintString(hints, m.Key, host)
}

func (m *hintsBuilder) getStreamHost(hints mapstr.M, streamName string) string {
	key := fmt.Sprintf("%v.%v", streamName, host)
	return utils.GetHintString(hints, m.Key, key)
}

func (m *hintsBuilder) getPeriod(hints mapstr.M) string {
	return utils.GetHintString(hints, m.Key, period)
}

func (m *hintsBuilder) getStreamPeriod(hints mapstr.M, streamName string) string {
	key := fmt.Sprintf("%v.%v", streamName, period)
	return utils.GetHintString(hints, m.Key, key)
}

func (m *hintsBuilder) getNamespace(hints mapstr.M) string {
	return utils.GetHintString(hints, m.Key, namespace)
}

func (m *hintsBuilder) getStreamNamespace(hints mapstr.M, streamName string) string {
	key := fmt.Sprintf("%v.%v", streamName, namespace)
	return utils.GetHintString(hints, m.Key, key)
}

func (m *hintsBuilder) getTimeout(hints mapstr.M) string {
	return utils.GetHintString(hints, m.Key, timeout)
}

func (m *hintsBuilder) getStreamTimeout(hints mapstr.M, streamName string) string {
	key := fmt.Sprintf("%v.%v", streamName, timeout)
	return utils.GetHintString(hints, m.Key, key)
}

func (m *hintsBuilder) getMetricspath(hints mapstr.M) string {
	return utils.GetHintString(hints, m.Key, metricspath)
}

func (m *hintsBuilder) getStreamMetricspath(hints mapstr.M, streamName string) string {
	key := fmt.Sprintf("%v.%v", streamName, metricspath)
	return utils.GetHintString(hints, m.Key, key)
}

func (m *hintsBuilder) getUsername(hints mapstr.M) string {
	return utils.GetHintString(hints, m.Key, username)
}

func (m *hintsBuilder) getStreamUsername(hints mapstr.M, streamName string) string {
	key := fmt.Sprintf("%v.%v", streamName, username)
	return utils.GetHintString(hints, m.Key, key)
}

func (m *hintsBuilder) getPassword(hints mapstr.M) string {
	return utils.GetHintString(hints, m.Key, password)
}

func (m *hintsBuilder) getStreamPassword(hints mapstr.M, streamName string) string {
	key := fmt.Sprintf("%v.%v", streamName, password)
	return utils.GetHintString(hints, m.Key, key)
}

func (m *hintsBuilder) getFromMeta(value string, kubeMeta mapstr.M) string {
	if value == "" {
		return ""
	}
	r := regexp.MustCompile(`\${([^{}]+)}`)
	matches := r.FindAllString(value, -1)
	for _, match := range matches {
		key := strings.TrimSuffix(strings.TrimPrefix(match, "${kubernetes."), "}")
		val, err := kubeMeta.GetValue(key)
		if err != nil {
			// TODO: add logging here
			return ""
		}
		hintVal, ok := val.(string)
		if !ok {
			// TODO: add logging here
			return ""
		}
		value = strings.Replace(value, match, hintVal, -1)
	}
	return value
}

// GenerateHintsMapping gets a hint's map extracted from the annotations and constructs the final
// hints' mapping to be emmited.
func GenerateHintsMapping(hints mapstr.M, kubeMeta mapstr.M, logger *logp.Logger, containerID string) mapstr.M {
	builder := hintsBuilder{
		Key:    "hints", // consider doing it a configurable,
		logger: logger,
	}

	hintsMapping := mapstr.M{}
	if containerID != "" {
		hintsMapping.Put("container_id", containerID)
	}

	integration := builder.getIntegration(hints)
	if integration == "" {
		return hintsMapping
	}
	integrationHints := mapstr.M{
		"enabled": true,
	}

	// TODO: add support for processors
	// is processor input specific or data_stream specific ???
	// Processors should be data_stream specific.
	// Add a basic processor as a base like:
	//- add_fields:
	//	  target: kubernetes
	//	  fields:
	//	    hints: true
	// Blocked by https://github.com/elastic/elastic-agent/issues/735

	integrationHost := builder.getFromMeta(builder.getHost(hints), kubeMeta)
	if integrationHost != "" {
		integrationHints.Put(host, integrationHost)
	}
	integrationPeriod := builder.getFromMeta(builder.getPeriod(hints), kubeMeta)
	if integrationPeriod != "" {
		integrationHints.Put(period, integrationPeriod)
	}
	integrationTimeout := builder.getFromMeta(builder.getTimeout(hints), kubeMeta)
	if integrationTimeout != "" {
		integrationHints.Put(timeout, integrationTimeout)
	}
	integrationMetricsPath := builder.getFromMeta(builder.getMetricspath(hints), kubeMeta)
	if integrationMetricsPath != "" {
		integrationHints.Put(metricspath, integrationMetricsPath)
	}
	integrationUsername := builder.getFromMeta(builder.getUsername(hints), kubeMeta)
	if integrationUsername != "" {
		integrationHints.Put(username, integrationUsername)
	}
	integrationPassword := builder.getFromMeta(builder.getPassword(hints), kubeMeta)
	if integrationPassword != "" {
		integrationHints.Put(password, integrationPassword)
	}

	dataStreams := builder.getDataStreams(hints)
	for _, dataStream := range dataStreams {
		streamHints := mapstr.M{
			"enabled": true,
		}
		if integrationPeriod != "" {
			streamHints.Put(period, integrationPeriod)
		}
		if integrationHost != "" {
			streamHints.Put(host, integrationHost)
		}
		if integrationTimeout != "" {
			streamHints.Put(timeout, integrationTimeout)
		}
		if integrationMetricsPath != "" {
			streamHints.Put(metricspath, integrationMetricsPath)
		}
		if integrationUsername != "" {
			streamHints.Put(username, integrationUsername)
		}
		if integrationPassword != "" {
			streamHints.Put(password, integrationPassword)
		}

		streamPeriod := builder.getFromMeta(builder.getStreamPeriod(hints, dataStream), kubeMeta)
		if streamPeriod != "" {
			streamHints.Put(period, streamPeriod)
		}
		streamHost := builder.getFromMeta(builder.getStreamHost(hints, dataStream), kubeMeta)
		if streamHost != "" {
			streamHints.Put(host, streamHost)
		}
		streamTimeout := builder.getFromMeta(builder.getStreamTimeout(hints, dataStream), kubeMeta)
		if streamTimeout != "" {
			streamHints.Put(timeout, streamTimeout)
		}
		streamMetricsPath := builder.getFromMeta(builder.getStreamMetricspath(hints, dataStream), kubeMeta)
		if streamMetricsPath != "" {
			streamHints.Put(metricspath, streamMetricsPath)
		}
		streamUsername := builder.getFromMeta(builder.getStreamUsername(hints, dataStream), kubeMeta)
		if streamUsername != "" {
			streamHints.Put(username, streamUsername)
		}
		streamPassword := builder.getFromMeta(builder.getStreamPassword(hints, dataStream), kubeMeta)
		if streamPassword != "" {
			streamHints.Put(password, streamPassword)
		}
		integrationHints.Put(dataStream, streamHints)

	}

	hintsMapping.Put(integration, integrationHints)

	return hintsMapping
}
