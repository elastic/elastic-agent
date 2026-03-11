package translate

import (
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/stretchr/testify/require"
)

func TestKafkaTranslationLogic(t *testing.T) {

	testCases := []struct {
		name        string
		input       string
		expectedMap map[string]any
	}{{
		name: "basic kafka translation logic",
		input: `
hosts: ["kafka1:9092", "kafka2:9092", "kafka3:9092"]
topic: static-topic
required_acks: 1
compression: gzip
max_message_bytes: 1000000`,
		expectedMap: map[string]any{
			"brokers":   []string{"kafka1:9092", "kafka2:9092", "kafka3:9092"},
			"topic":     "static-topic",
			"client_id": "beats",
			"metadata": map[string]any{
				"full":             false,
				"refresh_interval": 10 * time.Minute,
				"retry": map[string]any{
					"backoff": 250 * time.Millisecond,
					"max":     3,
				},
			},
			"producer": map[string]any{
				"compression": "gzip",
				"compression_param": map[string]any{
					"level": 4,
				},
				"max_message_bytes": 1000000,
				"required_acks":     1,
			},
			"protocol_version": "2.1.0",
			"retry_on_failure": map[string]any{
				"initial_interval": 1 * time.Second,
				"max_interval":     60 * time.Second,
			},
			"sending_queue": map[string]any{
				"batch": map[string]any{
					"flush_timeout": "10s",
					"max_size":      2048,
				},
				"queue_size": 3200,
			},
			"timeout": 10 * time.Second,
		},
	},
		{
			name: "when username and password are provided",
			input: `
hosts: ["kafka1:9092", "kafka2:9092", "kafka3:9092"]
topic: static-topic
required_acks: 1
compression: gzip
username: elastic
password: changeme
max_message_bytes: 1000000`,
			expectedMap: map[string]any{
				"brokers":   []string{"kafka1:9092", "kafka2:9092", "kafka3:9092"},
				"topic":     "static-topic",
				"client_id": "beats",
				"metadata": map[string]any{
					"full":             false,
					"refresh_interval": 10 * time.Minute,
					"retry": map[string]any{
						"backoff": 250 * time.Millisecond,
						"max":     3,
					},
				},
				"producer": map[string]any{
					"compression": "gzip",
					"compression_param": map[string]any{
						"level": 4,
					},
					"max_message_bytes": 1000000,
					"required_acks":     1,
				},
				"protocol_version": "2.1.0",
				"retry_on_failure": map[string]any{
					"initial_interval": 1 * time.Second,
					"max_interval":     60 * time.Second,
				},
				"sending_queue": map[string]any{
					"batch": map[string]any{
						"flush_timeout": "10s",
						"max_size":      2048,
					},
					"queue_size": 3200,
				},
				"timeout": 10 * time.Second,
				"auth": map[string]any{
					"sasl": map[string]any{
						"username":  "elastic",
						"password":  "changeme",
						"mechanism": "PLAIN",
					},
				},
			},
		},
	}

	for _, testc := range testCases {
		t.Run(testc.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(testc.input)
			require.NoError(t, err, "error creating kafka config")
			gotMap, err := KafkaToOTelConfig(cfg, logp.NewNopLogger())
			require.NoError(t, err, "error translating kafka to kafka exporter")
			require.Equal(t, testc.expectedMap, gotMap)
		})
	}
}
