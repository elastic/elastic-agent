package translate

import (
	"fmt"

	"github.com/elastic/beats/v7/libbeat/outputs/kafka"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

func KafkaToOTelConfig(config *config.C, logger *logp.Logger) (map[string]any, error) {
	kConfig, err := kafka.ReadConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error reading kafka config: %w", err)
	}

	kafkaExporter := map[string]any{
		"brokers":          kConfig.Hosts,
		"client_id":        kConfig.ClientID,
		"protocol_version": kConfig.Version,
		"auth": map[string]any{
			"sasl": map[string]any{
				"username":  kConfig.Username,
				"password":  kConfig.Password,
				"mechanism": kConfig.Sasl.SaslMechanism,
			},
		},
		"sending_queue": map[string]any{
			"batch": map[string]any{
				"max_size":      kConfig.BulkMaxSize,
				"flush_timeout": getFlushTimeout(logger, config),
			},
			"queue_size": getQueueSize(logger, config),
		},
		"producer": map[string]any{
			"compression": kConfig.Compression,
			"compression_param": map[string]any{
				"level": kConfig.CompressionLevel,
			},
			"max_message_bytes": kConfig.MaxMessageBytes,
			"required_acks":     kConfig.RequiredACKs,
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
	}
	return kafkaExporter, nil
}
