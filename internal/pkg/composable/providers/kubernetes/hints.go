// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetes

import (
	"fmt"
	"github.com/elastic/elastic-agent-autodiscover/utils"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"regexp"
	"strings"
)

const (
	integration = "package"
	namespace   = "namespace"
	host        = "host"
	datastreams = "data_streams"
	period      = "period"
	timeout     = "timeout"
	// TODO: Do we support more complext values in dynamic variables resolution in Agent
	ssl            = "ssl"
	metricsfilters = "metrics_filters"
	metricspath    = "metrics_path"
	username       = "username"
	password       = "password"
	// TODO: Verify how streams and container logs work and add that option here

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

func (m *hintsBuilder) getPassword(hints mapstr.M, streamName string) string {
	key := fmt.Sprintf("%v.%v", streamName, password)
	return utils.GetHintString(hints, m.Key, key)
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
func GenerateHintsMapping(hints mapstr.M, kubeMeta mapstr.M, logger *logp.Logger) mapstr.M {
	builder := hintsBuilder{
		Key:    "hints", // consider doing it a configurable,
		logger: logger,
	}

	hintsMapping := mapstr.M{}

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

	integrationHost := builder.getFromMeta(builder.getHost(hints), kubeMeta)
	if integrationHost != "" {
		integrationHints.Put("host", integrationHost)
	}
	integrationPeriod := builder.getFromMeta(builder.getPeriod(hints), kubeMeta)
	if integrationPeriod != "" {
		integrationHints.Put("period", integrationPeriod)
	}

	// TODO: add more hints here

	dataStreams := builder.getDataStreams(hints)
	for _, dataStream := range dataStreams {
		streamHints := mapstr.M{
			"enabled": true,
		}
		if integrationPeriod != "" {
			streamHints.Put("period", integrationPeriod)
		}
		if integrationHost != "" {
			streamHints.Put("host", integrationHost)
		}

		streamPeriod := builder.getFromMeta(builder.getStreamPeriod(hints, dataStream), kubeMeta)
		if streamPeriod != "" {
			streamHints.Put("period", streamPeriod)
		}
		streamHost := builder.getFromMeta(builder.getStreamHost(hints, dataStream), kubeMeta)
		if streamHost != "" {
			streamHints.Put("host", streamHost)
		}
		integrationHints.Put(dataStream, streamHints)

		// TODO: add more hints here
	}

	hintsMapping.Put(integration, integrationHints)

	return hintsMapping
}
