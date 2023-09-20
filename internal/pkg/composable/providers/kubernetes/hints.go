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

// Generates the hints and processor mappings from provided pod annotation map
func GetHintsMapping(k8sMapping map[string]interface{}, logger *logp.Logger, prefix string, cID string) hintsData {
	hintData := hintsData{
		composableMapping: mapstr.M{},
		processors:        []mapstr.M{},
	}
	var hints mapstr.M
	var containerProcessors []mapstr.M

	if ann, ok := k8sMapping["annotations"]; ok {
		annotations, _ := ann.(mapstr.M)

		if containerEntries, err := annotations.GetValue(prefix + ".hints"); err == nil {
			entries, ok := containerEntries.(mapstr.M)
			if ok && len(entries) > 0 {
				for key := range entries {
					parts := strings.Split(key, "/")

					if len(parts) > 0 {
						if con, ok := k8sMapping["container"]; ok {
							containers, ok := con.(mapstr.M)
							if ok {
								if cname, err := containers.GetValue("name"); err == nil {
									if parts[0] == cname {
										// If there are hints like co.elastic.hints.<container_name>/ then add the values after the / to the corresponding container
										hints = utils.GenerateHints(annotations, parts[0], prefix)
										// Processors for specific container
										// We need to make an extra check if we have processors added only to the specific containers
										containerProcessors = utils.GetConfigs(annotations, prefix, "hints."+parts[0]+"/processors")

									} else {
										// If there are top level hints like co.elastic.hints/ then just add the values after the /
										hints = utils.GenerateHints(annotations, "", prefix)
									}
									if len(hints) > 0 {
										logger.Debugf("Extracted hints are :%v", hints)
										hintData.composableMapping = GenerateHintsMapping(hints, k8sMapping, logger, cID)
										logger.Debugf("Generated hints mappings are :%v", hintData.composableMapping)

										hintData.processors = utils.GetConfigs(annotations, prefix, processorhints)
										// Only if there are processors defined in a specific container we append them to the processors of the pod
										if len(containerProcessors) > 0 {
											hintData.processors = append(hintData.processors, containerProcessors...)
										}
										logger.Debugf("Generated Processors are :%v", hintData.processors)
									}
								}
							}

						}
					}

				}
			}

		}

	}
	return hintData
}
