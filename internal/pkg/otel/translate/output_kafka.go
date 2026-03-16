// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"errors"
	"fmt"

	"github.com/elastic/beats/v7/libbeat/common/fmtstr"
	"github.com/elastic/beats/v7/libbeat/outputs/kafka"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

func KafkaToOTelConfig(config *config.C, logger *logp.Logger) (map[string]any, error) {
	kConfig, err := kafka.ReadConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error reading kafka config: %w", err)
	}

	if err := checkUnsupportedKafkaConfig(config); err != nil {
		return nil, err
	}

	maxMessageBytes := 100000
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
		"topic":   kConfig.Topic,
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

	return kafkaExporter, nil
}

// log warning for unsupported config
func checkUnsupportedKafkaConfig(cfg *config.C) error {

	// topic field always exists here, otherwise Validate function above throws an error
	str, err := cfg.String("topic", -1)
	if err != nil {
		return err
	}

	fmtstr, err := fmtstr.CompileEvent(str)
	if err != nil {
		return err
	}

	if !fmtstr.IsConst() {
		return fmt.Errorf("dynamic topic selection is currently not supported: %w", errors.ErrUnsupported)
	}

	if cfg.HasField("partition") {
		return fmt.Errorf("partition is currently not supported: %w", errors.ErrUnsupported)
	} else if cfg.HasField("keep_alive") {
		return fmt.Errorf("keep_alive is currently not supported: %w", errors.ErrUnsupported)
	} else if cfg.HasField("headers") {
		return fmt.Errorf("headers is currently not supported: %w", errors.ErrUnsupported)
	}

	return nil
}
