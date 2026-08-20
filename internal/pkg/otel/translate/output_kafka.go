// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"reflect"
	"strings"
	"time"

	otelcomponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configopaque"

	"github.com/go-viper/mapstructure/v2"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/oauth2clientauthextension"

	"github.com/elastic/beats/v7/libbeat/common/fmtstr"
	"github.com/elastic/beats/v7/libbeat/outputs/kafka"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

const transformProcessorType = "transform"
const oauth2ClientExtensionType = "oauth2client"

// KafkaToOTelConfig translates kafka output to OTel config
// It returns kafka exporter, transform processor (if required), extension config (if required) and error
func KafkaToOTelConfig(config *config.C, outputName string, logger *logp.Logger) (exporterCfg map[string]any, processorCfg map[string]any, extensionCfg map[string]any, err error) {
	kConfig, err := kafka.ReadConfig(config)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error reading kafka config: %w", err)
	}

	if err := checkUnsupportedKafkaConfig(config, logger); err != nil {
		return nil, nil, nil, err
	}

	maxMessageBytes := 1000000
	if kConfig.MaxMessageBytes != nil {
		maxMessageBytes = *kConfig.MaxMessageBytes
	}

	requiredAcks := 1
	if kConfig.RequiredACKs != nil {
		requiredAcks = *kConfig.RequiredACKs
	}

	var headers []map[string]any
	for _, header := range kConfig.Headers {
		headers = append(headers, map[string]any{
			"name":  header.Key,
			"value": header.Value,
		})
	}

	kafkaExporter := map[string]any{
		"brokers":          kConfig.Hosts,
		"client_id":        kConfig.ClientID,
		"protocol_version": string(kConfig.Version),
		"sending_queue": map[string]any{
			"batch": map[string]any{
				"max_size":      kConfig.BulkMaxSize,
				"flush_timeout": getFlushTimeout(logger, config),
				"min_size":      min(getFlushMinEvents(logger, config), kConfig.BulkMaxSize), // queue.mem.flush.min_events, capped at max_size
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
		},
		"timeout": kConfig.BrokerTimeout,
		"logs": map[string]any{
			"topic":    kConfig.Topic,
			"encoding": "raw",
		},
	}

	extensionCfg = make(map[string]any)

	// Set SASL authentication
	if strings.ToUpper(kConfig.Sasl.SaslMechanism) == "OAUTHBEARER" {
		kafkaExporter["auth"] = map[string]any{
			"sasl": map[string]any{
				"mechanism":                "OAUTHBEARER",
				"oauthbearer_token_source": getOauth2ClientExtensionID(outputName).String(),
			},
		}

		oauthCfg, err := config.Child("oauth2client", -1)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("oauth2client config is required when sasl.mechanism is OAUTHBEARER: %w", err)
		}
		oauth2ClientExtensionCfg, err := getOauth2ClientExtensionConfig(oauthCfg, outputName)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error translating oauth2client extension config: %w", err)
		}
		maps.Copy(extensionCfg, oauth2ClientExtensionCfg)
	} else if kConfig.Username != "" {
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

	// Enables Kerberos authentication
	if kConfig.Kerberos.IsEnabled() {
		kafkaExporter["auth"] = map[string]any{
			"kerberos": getKerberosConfig(kConfig),
		}
	}

	tlsCfg, err := TLSToOTel(kConfig.TLS, logger)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error translating tls config :%w", err)
	}

	setIfNotNil(kafkaExporter, "tls", tlsCfg)
	setIfNotNil(kafkaExporter, "record_headers", headers)

	// Set partitioner extension config
	partitionerExtensionCfg, err := getKafkaPartitionerExtensionConfig(kConfig.Partition, outputName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error translating kafka partitioner config: %w", err)
	}
	kafkaExporter["record_partitioner"] = map[string]any{
		"extension": getKafkaPartitionerExtensionID(outputName).String(),
	}
	extensionCfg[getKafkaPartitionerExtensionID(outputName).String()] = partitionerExtensionCfg

	// compiles topic and validates against any malformed strings
	fmtstr, err := fmtstr.CompileEvent(kConfig.Topic)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not parse topic: %w", err)
	}

	if !fmtstr.IsConst() {
		kafkaExporter["topic_from_attribute"] = "topic"
		processor, err := dynamicTopicSetterProcessor(kConfig.Topic, outputName)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("error translating kafka topic: %w", err)
		}
		// delete topic set under logs
		delete(kafkaExporter["logs"].(map[string]any), "topic")
		return kafkaExporter, processor, extensionCfg, nil
	}

	return kafkaExporter, nil, extensionCfg, nil
}

func getKerberosConfig(kConfig *kafka.KafkaConfig) map[string]any {
	if !kConfig.Kerberos.IsEnabled() {
		return nil
	}

	useKeyTab := kConfig.Kerberos.AuthType.String() == "keytab"

	return map[string]any{
		"service_name":             kConfig.Kerberos.ServiceName,
		"realm":                    kConfig.Kerberos.Realm,
		"username":                 kConfig.Kerberos.Username,
		"password":                 kConfig.Kerberos.Password,
		"config_file":              kConfig.Kerberos.ConfigPath,
		"disable_fast_negotiation": !kConfig.Kerberos.EnableFAST,
		"keytab_file":              kConfig.Kerberos.KeyTabPath,
		"use_keytab":               useKeyTab,
	}
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

func getKafkaPartitionerExtensionConfig(partition map[string]*config.C, _ string) (extensionCfg map[string]any, err error) {
	if len(partition) == 0 {
		// default use `hash` partitioner + all partitions (block if unreachable)
		return map[string]any{}, nil
	}

	// extract partitioner from config
	var name string
	var config *config.C
	for n, c := range partition {
		name, config = n, c
	}

	var partitionMap map[string]any = make(map[string]any)
	err = config.Unpack(&partitionMap)
	if err != nil {
		return nil, fmt.Errorf("error unpacking partition config: %w", err)
	}

	partitionerCfg := map[string]any{
		name: partitionMap,
	}

	return partitionerCfg, nil
}

func getOauth2ClientExtensionConfig(cfg *config.C, outputName string) (extensionCfg map[string]any, err error) {
	var oauthMap map[string]any
	err = cfg.Unpack(&oauthMap)
	if err != nil {
		return nil, fmt.Errorf("error unpacking oauth2client extension config: %w", err)
	}

	// Default settings are taken from https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/cbc5a870545d7a25c8bbd62404a025978c907d57/extension/oauth2clientauthextension/factory.go#L28
	defaultConfig := oauth2clientauthextension.Config{
		ExpiryBuffer: 5 * time.Minute,
	}

	err = mapstructure.Decode(oauthMap, &defaultConfig)
	if err != nil {
		return nil, fmt.Errorf("error decoding oauth2client extension config: %w", err)
	}

	if err = defaultConfig.Validate(); err != nil {
		return nil, fmt.Errorf("error validating oauth2client extension config: %w", err)
	}

	// Convert config back to map[string]any
	if err = mapstructure.Decode(defaultConfig, &oauthMap); err != nil {
		return nil, fmt.Errorf("error encoding oauth2client extension config: %w", err)
	}

	var newMap map[string]any
	encoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:     &newMap,
		DecodeHook: oauth2MapEncodeHook(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed creating encoder: %w", err)
	}
	if err = encoder.Decode(oauthMap); err != nil {
		return nil, fmt.Errorf("error encoding oauth2client extension config: %w", err)
	}

	extensionID := getOauth2ClientExtensionID(outputName)
	return map[string]any{
		extensionID.String(): newMap,
	}, nil
}

func oauth2MapEncodeHook() mapstructure.DecodeHookFunc {
	return func(_ reflect.Type, _ reflect.Type, data any) (any, error) {
		switch v := data.(type) {
		case time.Duration:
			return v.String(), nil
		case configopaque.String:
			return string(v), nil
		case url.URL:
			return v.String(), nil
		default:
			return data, nil
		}
	}
}

func getOauth2ClientExtensionID(outputName string) otelcomponent.ID {
	extensionName := fmt.Sprintf("%s%s", OtelNamePrefix, outputName)
	return otelcomponent.NewIDWithName(otelcomponent.MustNewType(oauth2ClientExtensionType), extensionName)
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

// getKafkaPartitionerExtensionID returns the id for kafkapartitioner extension
// outputName here is name of the output defined in elastic-agent.yml. For ex: default, monitoring
func getKafkaPartitionerExtensionID(outputName string) otelcomponent.ID {
	extensionName := fmt.Sprintf("%s%s", OtelNamePrefix, outputName)
	return otelcomponent.NewIDWithName(otelcomponent.MustNewType("kafkapartitioner"), extensionName)
}

// log warning for unsupported config
func checkUnsupportedKafkaConfig(cfg *config.C, logger *logp.Logger) error {

	if cfg.HasField("keep_alive") {
		return fmt.Errorf("keep_alive is currently not supported: %w", errors.ErrUnsupported)
	} else if cfg.HasField("timeout") {
		return fmt.Errorf("timeout is currently not supported: %w", errors.ErrUnsupported)
	} else if value, err := cfg.Child("ssl", -1); err == nil {
		if value.HasField("ca_trusted_fingerprint") {
			return fmt.Errorf("ca_trusted_fingerprint is currently not supported: %w", errors.ErrUnsupported)
		} else if value.HasField("ca_sha_256") {
			return fmt.Errorf("ca_sha_256 is currently not supported: %w", errors.ErrUnsupported)
		}
	}

	if cfg.HasField("bulk_flush_frequency") {
		logger.Warn("bulk_flush_frequency is deprecated")
	}

	return nil
}
