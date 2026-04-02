// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"errors"
	"fmt"
	"strings"

	otelcomponent "go.opentelemetry.io/collector/component"

	"github.com/elastic/beats/v7/libbeat/common/fmtstr"
	"github.com/elastic/beats/v7/libbeat/outputs/kafka"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

const transformProcessorType = "transform"

// KafkaToOTelConfig translates kafka output to OTel config
// It returns kafka exporter, transform processor (if required) and error
func KafkaToOTelConfig(config *config.C, outputName string, logger *logp.Logger) (map[string]any, map[string]any, error) {
	kConfig, err := kafka.ReadConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading kafka config: %w", err)
	}

	if err := checkUnsupportedKafkaConfig(config, logger); err != nil {
		return nil, nil, err
	}

	maxMessageBytes := 1000000
	if kConfig.MaxMessageBytes != nil {
		maxMessageBytes = *kConfig.MaxMessageBytes
	}

	requiredAcks := 1
	if kConfig.RequiredACKs != nil {
		requiredAcks = *kConfig.RequiredACKs
	}

	kafkaExporter := map[string]any{
		"brokers":          kConfig.Hosts,
		"client_id":        kConfig.ClientID,
		"protocol_version": string(kConfig.Version),
		"sending_queue": map[string]any{
			"batch": map[string]any{
				"max_size":      kConfig.BulkMaxSize,
				"flush_timeout": getFlushTimeout(logger, config),
				"min_size":      0, // 0 means immediately trigger a flush
				"sizer":         "items",
			},
			"queue_size": getQueueSize(logger, config),
		},
		"producer": map[string]any{
			"compression": kConfig.Compression,
			"compression_params": map[string]any{
				"level": kConfig.CompressionLevel,
			},
			"max_message_bytes": maxMessageBytes,
			"required_acks":     requiredAcks,
		},
		"retry_on_failure": map[string]any{
			"initial_interval": kConfig.Backoff.Init,
			"max_interval":     kConfig.Backoff.Max,
		},
		"metadata": map[string]any{
			"refresh_interval": kConfig.Metadata.RefreshFreq,
			"full":             kConfig.Metadata.Full,
			"retry": map[string]any{
				"max":     kConfig.Metadata.Retry.Max,
				"backoff": kConfig.Metadata.Retry.Backoff,
			},
		},
		"timeout": kConfig.BrokerTimeout,
		"logs": map[string]any{
			"topic": kConfig.Topic,
		},
	}

	if kConfig.Username != "" {
		if kConfig.Sasl.SaslMechanism == "" {
			kConfig.Sasl.SaslMechanism = "PLAIN"
		}
		kafkaExporter["auth"] = map[string]any{
			"sasl": map[string]any{
				"username":  kConfig.Username,
				"password":  kConfig.Password,
				"mechanism": kConfig.Sasl.SaslMechanism,
			},
		}
	}

	// compiles topic and validates against any malformed strings
	fmtstr, err := fmtstr.CompileEvent(kConfig.Topic)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse topic: %w", err)
	}

	if !fmtstr.IsConst() {
		kafkaExporter["topic_from_attribute"] = "topic"
		processor, err := dynamicTopicSetterProcessor(kConfig.Topic, outputName)
		if err != nil {
			return nil, nil, fmt.Errorf("error translating kafka topic: %w", err)
		}
		// delete topic set under logs
		delete(kafkaExporter, "logs")
		return kafkaExporter, processor, nil
	}
	return kafkaExporter, nil, nil
}

// dynamicTopicSetterProcessor parses topic field with dynamic values such as %{[data_stream.type]}
// It translates this behavior onto a transform processor defined here
// More about transform processor https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/transformprocessor
func dynamicTopicSetterProcessor(topic string, outputName string) (map[string]any, error) {
	logStatements := []string{}

	lexer := fmtstr.MakeLexer(topic)
	defer lexer.Finish()

	tokens, err := fmtstr.ParseRawTokens(lexer)
	if err != nil {
		return nil, fmt.Errorf("error parsing token:%w", err)
	}

	pendingLiteral := ""
	fieldExpr := func(v fmtstr.VariableToken) string {
		return getLogBody(extractField(string(v)))
	}

	for _, tok := range tokens {
		switch t := tok.(type) {
		case string:
			pendingLiteral += t
		case fmtstr.VariableToken:
			f := fieldExpr(t)
			if len(logStatements) == 0 {
				if pendingLiteral != "" {
					// First placeholder: set topic = literal + field
					logStatements = append(logStatements, fmt.Sprintf(
						`set(resource.attributes["topic"], Concat(["%s", %s], ""))`,
						pendingLiteral, f))
				} else {
					// First placeholder: set topic = field
					logStatements = append(logStatements, fmt.Sprintf(
						`set(resource.attributes["topic"], %s)`, f))
				}
			} else {
				// Subsequent placeholder: set topic = topic + literal + field
				logStatements = append(logStatements, fmt.Sprintf(
					`set(resource.attributes["topic"], Concat([resource.attributes["topic"], %s], "%s"))`,
					f, pendingLiteral))
			}
			pendingLiteral = ""
		default:
			return nil, fmt.Errorf("unexpected token type %T in kafka topic format", tok)
		}
	}

	// check if any more content is left after all fields are parsed
	if len(logStatements) > 0 && pendingLiteral != "" {
		logStatements = append(logStatements, fmt.Sprintf(
			`set(resource.attributes["topic"], Concat([resource.attributes["topic"], "%s"], ""))`,
			pendingLiteral))
	}

	if len(logStatements) == 0 {
		return nil, fmt.Errorf("there are no statements")
	}

	return map[string]any{
		getTransformProcessorID(outputName).String(): map[string]any{
			"error_mode":     "ignore",
			"log_statements": logStatements,
		},
	}, nil
}

func extractField(field string) string {
	if len(field) == 0 {
		return ""
	}

	switch field[0] {
	case '[':
		data, _ := fmtstr.ParseEventPath(field)
		return data
	case '+':
		// TODO parse time stamp
		return ""
	}

	return ""
}

func getLogBody(field string) string {
	query := strings.Split(field, ".")

	logBody := []string{"log.body"}
	for _, q := range query {
		logBody = append(logBody, fmt.Sprintf(`["%s"]`, q))
	}
	return strings.Join(logBody, "")
}

// getTransformProcessorID returns the id for transform processor
func getTransformProcessorID(outputName string) otelcomponent.ID {
	extensionName := fmt.Sprintf("%s%s", OtelNamePrefix, outputName)
	return otelcomponent.NewIDWithName(otelcomponent.MustNewType(transformProcessorType), extensionName)
}

// log warning for unsupported config
func checkUnsupportedKafkaConfig(cfg *config.C, logger *logp.Logger) error {

	if cfg.HasField("partition") {
		return fmt.Errorf("partition is currently not supported: %w", errors.ErrUnsupported)
	} else if cfg.HasField("keep_alive") {
		return fmt.Errorf("keep_alive is currently not supported: %w", errors.ErrUnsupported)
	} else if cfg.HasField("headers") {
		return fmt.Errorf("headers is currently not supported: %w", errors.ErrUnsupported)
	} else if cfg.HasField("timeout") {
		return fmt.Errorf("timeout is currently not supported: %w", errors.ErrUnsupported)
	} else if cfg.HasField("ssl") {
		return fmt.Errorf("ssl parameters are currently not supported: %w", errors.ErrUnsupported)
	} else if cfg.HasField("bulk_flush_frequency") {
		logger.Warn("bulk_flush_frequency is deprecated")
	}

	return nil
}
