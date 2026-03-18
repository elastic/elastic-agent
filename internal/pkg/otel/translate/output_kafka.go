// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"errors"
	"fmt"
	"strings"

	"github.com/elastic/beats/v7/libbeat/common/fmtstr"
	"github.com/elastic/beats/v7/libbeat/outputs/kafka"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

// KafkaToOTelConfig translate kafka output to OTel config
// It returns config for kafka exporter, tranform processor and error
func KafkaToOTelConfig(config *config.C, logger *logp.Logger) (map[string]any, map[string]any, error) {
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
		processor := setDynamicTopic(fmtstr, kConfig.Topic)
		return kafkaExporter, processor, nil
	}
	return kafkaExporter, nil, nil
}

// TODO: Default value and special operation is not supported in this translation logic yet
// set dynamic topic returns a transform processor
func setDynamicTopic(fs *fmtstr.EventFormatString, topic string) map[string]any {
	fields := fs.Fields()
	if len(fields) < 1 {
		return nil
	}

	content := topic
	logStatements := []string{}

	for fieldIndex := 0; fieldIndex < len(fields); {
		idxPercent := strings.Index(content, "%")
		if idxPercent == -1 {
			break
		}
		// Require %{...}; find closing }
		if len(content) <= idxPercent+1 || content[idxPercent+1] != '{' {
			content = content[idxPercent+1:]
			continue
		}
		idxClose := strings.Index(content[idxPercent+2:], "}")
		// Ideally this should never happen because we have identified len(fields) exists
		if idxClose == -1 {
			break
		}

		idxClose += idxPercent + 2 // position of '}' in content
		literalBefore := content[:idxPercent]

		// Advance past "%{...}"
		content = content[idxClose+1:]

		if len(logStatements) == 0 {
			if literalBefore == "" {
				// First placeholder: set topic = field
				logStatements = append(logStatements, fmt.Sprintf(`set(resource.attributes["topic"], log.body["%s"])`, fields[fieldIndex]))
			} else {
				// First placeholder: set topic =  literal + field
				logStatements = append(logStatements, fmt.Sprintf(`set(resource.attributes["topic"], Concat(["%s", log.body["%s"]], ""))`, literalBefore, fields[fieldIndex]))
			}
		} else {
			// Subsequent placeholder: set topic =  topic + field
			if literalBefore == "" {
				logStatements = append(logStatements, fmt.Sprintf(`set(resource.attributes["topic"], Concat([resource.attributes["topic"], log.body["%s"]], ""))`, fields[fieldIndex]))
			} else {
				// Subsequent placeholder: set topic =  topic + literal + field
				logStatements = append(logStatements, fmt.Sprintf(`set(resource.attributes["topic"], Concat([resource.attributes["topic"], log.body["%s"]], "%s"))`, fields[fieldIndex], literalBefore))
			}

		}

		// check if any more content is left after all fields are indexed
		if fieldIndex == (len(fields)-1) && len(content) != 0 {
			logStatements = append(logStatements, fmt.Sprintf(`set(resource.attributes["topic"], Concat([resource.attributes["topic"], "%s"], ""))`, content))
		}
		fieldIndex++
	}

	if len(logStatements) == 0 {
		return nil
	}

	return map[string]any{
		"transform": map[string]any{
			"error_mode":     "ignore",
			"log_statements": logStatements,
		},
	}
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
