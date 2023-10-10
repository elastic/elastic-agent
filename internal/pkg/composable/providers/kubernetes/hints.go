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
	stream      = "stream" // this is the container stream: stdout/stderr

	hints      = "hints"
	processors = "processors"
)

type hintsBuilder struct {
	Key string

	logger *logp.Logger
}

func (m *hintsBuilder) getIntegration(hints mapstr.M) string {
	return utils.GetHintString(hints, m.Key, integration)
}

func (m *hintsBuilder) getDataStreams(hints mapstr.M) []string {
	ds := utils.GetHintAsList(hints, m.Key, datastreams)
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

func (m *hintsBuilder) getContainerStream(hints mapstr.M) string {
	return utils.GetHintString(hints, m.Key, stream)
}

func (m *hintsBuilder) getStreamContainerStream(hints mapstr.M, streamName string) string {
	key := fmt.Sprintf("%v.%v", streamName, stream)
	return utils.GetHintString(hints, m.Key, key)
}

// Replace hints like `'${kubernetes.pod.ip}:6379'` with the actual values from the resource metadata.
// So if you replace the `${kubernetes.pod.ip}` part with the value from the Pod's metadata
// you end up with sth like `10.28.90.345:6379`
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
			m.logger.Debugf("cannot retrieve key from k8smeta: %v", key)
			return ""
		}
		hintVal, ok := val.(string)
		if !ok {
			m.logger.Debugf("cannot convert value into string: %v", val)
			return ""
		}
		value = strings.Replace(value, match, hintVal, -1)
	}
	return value
}

// GenerateHintsMapping gets a hint's map extracted from the annotations and constructs the final
// hints' mapping to be emitted.
func GenerateHintsMapping(hints mapstr.M, kubeMeta mapstr.M, logger *logp.Logger, containerID string) mapstr.M {
	builder := hintsBuilder{
		Key:    "hints", // consider doing it a configurable,
		logger: logger,
	}

	hintsMapping := mapstr.M{}
	integration := builder.getIntegration(hints)
	if integration == "" {
		return hintsMapping
	}
	integrationHints := mapstr.M{}

	if containerID != "" {
		_, _ = hintsMapping.Put("container_id", containerID)
		// Add the default container log fallback to enable any template which defines
		// a log input with a `"${kubernetes.hints.container_logs.enabled} == true"` condition
		_, _ = integrationHints.Put("container_logs.enabled", true)
	}

	integrationHost := builder.getFromMeta(builder.getHost(hints), kubeMeta)
	if integrationHost != "" {
		_, _ = integrationHints.Put(host, integrationHost)
	}
	integrationPeriod := builder.getFromMeta(builder.getPeriod(hints), kubeMeta)
	if integrationPeriod != "" {
		_, _ = integrationHints.Put(period, integrationPeriod)
	}
	integrationTimeout := builder.getFromMeta(builder.getTimeout(hints), kubeMeta)
	if integrationTimeout != "" {
		_, _ = integrationHints.Put(timeout, integrationTimeout)
	}
	integrationMetricsPath := builder.getFromMeta(builder.getMetricspath(hints), kubeMeta)
	if integrationMetricsPath != "" {
		_, _ = integrationHints.Put(metricspath, integrationMetricsPath)
	}
	integrationUsername := builder.getFromMeta(builder.getUsername(hints), kubeMeta)
	if integrationUsername != "" {
		_, _ = integrationHints.Put(username, integrationUsername)
	}
	integrationPassword := builder.getFromMeta(builder.getPassword(hints), kubeMeta)
	if integrationPassword != "" {
		_, _ = integrationHints.Put(password, integrationPassword)
	}
	integrationContainerStream := builder.getFromMeta(builder.getContainerStream(hints), kubeMeta)
	if integrationContainerStream != "" {
		_, _ = integrationHints.Put(stream, integrationContainerStream)
	}

	dataStreams := builder.getDataStreams(hints)
	if len(dataStreams) == 0 {
		_, _ = integrationHints.Put("enabled", true)
	}
	for _, dataStream := range dataStreams {
		streamHints := mapstr.M{
			"enabled": true,
		}
		if integrationPeriod != "" {
			_, _ = streamHints.Put(period, integrationPeriod)
		}
		if integrationHost != "" {
			_, _ = streamHints.Put(host, integrationHost)
		}
		if integrationTimeout != "" {
			_, _ = streamHints.Put(timeout, integrationTimeout)
		}
		if integrationMetricsPath != "" {
			_, _ = streamHints.Put(metricspath, integrationMetricsPath)
		}
		if integrationUsername != "" {
			_, _ = streamHints.Put(username, integrationUsername)
		}
		if integrationPassword != "" {
			_, _ = streamHints.Put(password, integrationPassword)
		}
		if integrationContainerStream != "" {
			_, _ = streamHints.Put(stream, integrationContainerStream)
		}

		streamPeriod := builder.getFromMeta(builder.getStreamPeriod(hints, dataStream), kubeMeta)
		if streamPeriod != "" {
			_, _ = streamHints.Put(period, streamPeriod)
		}
		streamHost := builder.getFromMeta(builder.getStreamHost(hints, dataStream), kubeMeta)
		if streamHost != "" {
			_, _ = streamHints.Put(host, streamHost)
		}
		streamTimeout := builder.getFromMeta(builder.getStreamTimeout(hints, dataStream), kubeMeta)
		if streamTimeout != "" {
			_, _ = streamHints.Put(timeout, streamTimeout)
		}
		streamMetricsPath := builder.getFromMeta(builder.getStreamMetricspath(hints, dataStream), kubeMeta)
		if streamMetricsPath != "" {
			_, _ = streamHints.Put(metricspath, streamMetricsPath)
		}
		streamUsername := builder.getFromMeta(builder.getStreamUsername(hints, dataStream), kubeMeta)
		if streamUsername != "" {
			_, _ = streamHints.Put(username, streamUsername)
		}
		streamPassword := builder.getFromMeta(builder.getStreamPassword(hints, dataStream), kubeMeta)
		if streamPassword != "" {
			_, _ = streamHints.Put(password, streamPassword)
		}
		streamContainerStream := builder.getFromMeta(builder.getStreamContainerStream(hints, dataStream), kubeMeta)
		if streamContainerStream != "" {
			_, _ = streamHints.Put(stream, streamContainerStream)
		}
		_, _ = integrationHints.Put(dataStream, streamHints)

	}

	_, _ = hintsMapping.Put(integration, integrationHints)

	return hintsMapping
}

// GetHintsMapping Generates the hints and processor mappings from provided pod annotation map
func GetHintsMapping(k8sMapping map[string]interface{}, logger *logp.Logger, prefix string, cID string) hintsData {
	hintData := hintsData{
		composableMapping: mapstr.M{},
		processors:        []mapstr.M{},
	}

	ann, ok := k8sMapping["annotations"]
	if !ok {
		return hintData
	}
	annotations, _ := ann.(mapstr.M)

	cName := ""
	cHost := ""
	// Get the name of the container from the metadata. We need it to extract the hints that affect it directly.
	// E.g. co.elastic.hints.<container-name>/host: "..."
	if con, ok := k8sMapping["container"]; ok {
		containers, _ := con.(mapstr.M)
		if name, err := containers.GetValue("name"); err == nil {
			cName = name.(string)
		}
		if cPort, err := containers.GetValue("port"); err == nil {
			// This is the default for the host value of a specific container.
			cHost = "${kubernetes.pod.ip}:" + cPort.(string)
		}
	}

	hintsExtracted := utils.GenerateHints(annotations, cName, prefix)
	if len(hintsExtracted) == 0 {
		return hintData
	}

	// Check if host exists. Otherwise, add default entry for it.
	if cHost != "" {
		if hintsValues, ok := hintsExtracted[hints].(mapstr.M); ok {
			if _, ok := hintsValues[host]; !ok {
				hintsValues[host] = cHost
			}
		} else {
			hintsExtracted[hints] = mapstr.M{
				host: cHost,
			}
		}
	}

	logger.Debugf("Extracted hints are :%v", hintsExtracted)

	hintData.composableMapping = GenerateHintsMapping(hintsExtracted, k8sMapping, logger, cID)
	logger.Debugf("Generated hints mappings :%v", hintData.composableMapping)

	hintData.processors = utils.GetConfigs(annotations, prefix, hints+"/"+processors)
	// We need to check the processors for the specific container, if they exist.
	if cName != "" {
		containerProcessors := utils.GetConfigs(annotations, prefix, hints+"."+cName+"/"+processors)
		if len(containerProcessors) > 0 {
			hintData.processors = append(hintData.processors, containerProcessors...)
		}
	}
	logger.Debugf("Generated Processors mapping :%v", hintData.processors)

	return hintData
}
