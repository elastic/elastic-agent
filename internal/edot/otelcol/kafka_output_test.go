// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package otelcol

import (
	"testing"

	configkafka "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/kafka/configkafka"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
)

// Regression test for https://github.com/elastic/sdh-beats/issues/7489:
// lz4 (and other codecs that don't support compression levels) must produce
// a ProducerConfig that passes OTel kafkaexporter validation after translation.
func TestKafkaOutputTranslationValidatesAgainstOTelExporter(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name: "lz4 without explicit compression_level",
			input: `
hosts: ["kafka1:9092"]
topic: test-topic
compression: lz4
`,
		},
		{
			name: "snappy without explicit compression_level",
			input: `
hosts: ["kafka1:9092"]
topic: test-topic
compression: snappy
`,
		},
		{
			name: "gzip without explicit compression_level",
			input: `
hosts: ["kafka1:9092"]
topic: test-topic
compression: gzip
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(tc.input)
			require.NoError(t, err)

			translatedMap, _, err := translate.KafkaToOTelConfig(cfg, "", logp.NewNopLogger())
			require.NoError(t, err)

			producerMap, ok := translatedMap["producer"].(map[string]any)
			require.True(t, ok, "translated config must contain a producer key")

			// Decode via confmap — the same path the OTel collector uses at startup.
			producerConf := confmap.NewFromStringMap(producerMap)
			producerCfg := configkafka.NewDefaultProducerConfig()
			require.NoError(t, producerConf.Unmarshal(&producerCfg))

			require.NoError(t, producerCfg.Validate(),
				"translated kafka producer config must be accepted by the OTel kafkaexporter")
		})
	}
}
