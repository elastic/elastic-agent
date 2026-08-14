// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configopaque"

	"github.com/elastic/beats/v7/libbeat/common/fmtstr"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
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
max_message_bytes: 1000000
headers:
- key: "some-key"
  value: "some value"
- key: "some-key"
  value: "another value"
`,
		expectedMap: map[string]any{
			"brokers": []string{"kafka1:9092", "kafka2:9092", "kafka3:9092"},
			"logs": map[string]any{
				"topic":    "static-topic",
				"encoding": "raw",
			},
			"client_id": "beats",
			"metadata": map[string]any{
				"refresh_interval": 10 * time.Minute,
			},
			"producer": map[string]any{
				"compression": "gzip",
				"compression_params": map[string]any{
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
					"min_size":      1600,
					"sizer":         "items",
				},
				"queue_size": 3200,
			},
			"timeout": 10 * time.Second,
			"record_headers": []map[string]any{
				{
					"name":  "some-key",
					"value": "some value",
				},
				{
					"name":  "some-key",
					"value": "another value",
				},
			},
			"record_partitioner": map[string]any{
				"extension": "kafkapartitioner/_agent-component/default",
			},
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
				"brokers": []string{"kafka1:9092", "kafka2:9092", "kafka3:9092"},
				"logs": map[string]any{
					"topic":    "static-topic",
					"encoding": "raw",
				},
				"client_id": "beats",
				"metadata": map[string]any{
					"refresh_interval": 10 * time.Minute,
				},
				"producer": map[string]any{
					"compression": "gzip",
					"compression_params": map[string]any{
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
						"sizer":         "items",
						"min_size":      1600,
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
				"record_partitioner": map[string]any{
					"extension": "kafkapartitioner/_agent-component/default",
				},
			},
		},
		{
			name: "when oauth2 is provided username auth is deferred",
			input: `
hosts: ["kafka1:9092"]
topic: static-topic
username: elastic
password: changeme
sasl.mechanism: OAUTHBEARER
oauth2client:
  client_id: my-client
  client_secret: my-secret
  token_url: https://example.com/oauth2/token
`,
			expectedMap: map[string]any{
				"brokers":   []string{"kafka1:9092"},
				"client_id": "beats",
				"logs": map[string]any{
					"topic":    "static-topic",
					"encoding": "raw",
				},
				"metadata": map[string]any{
					"refresh_interval": 10 * time.Minute,
				},
				"producer": map[string]any{
					"compression": "gzip",
					"compression_params": map[string]any{
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
						"sizer":         "items",
						"min_size":      1600,
					},
					"queue_size": 3200,
				},
				"timeout": 10 * time.Second,
				"auth": map[string]any{
					"sasl": map[string]any{
						"mechanism":                "OAUTHBEARER",
						"oauthbearer_token_source": "oauth2client/_agent-component/default",
					},
				},
				"record_partitioner": map[string]any{
					"extension": "kafkapartitioner/_agent-component/default",
				},
			},
		},
		{
			name: "when dynamic topic is provided",
			input: `
hosts: ["kafka1:9092", "kafka2:9092", "kafka3:9092"]
topic: "%{[data_stream.type]}-%{[data_stream.dataset]}-%{[data_stream.namespace]}"
required_acks: 1
compression: gzip
max_message_bytes: 1000000`,
			expectedMap: map[string]any{
				"brokers":              []string{"kafka1:9092", "kafka2:9092", "kafka3:9092"},
				"topic_from_attribute": "topic", // this field is an the addition
				"client_id":            "beats",
				"metadata": map[string]any{
					"refresh_interval": 10 * time.Minute,
				},
				"producer": map[string]any{
					"compression": "gzip",
					"compression_params": map[string]any{
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
						"sizer":         "items",
						"min_size":      1600,
					},
					"queue_size": 3200,
				},
				"logs": map[string]any{
					"encoding": "raw",
				},
				"timeout": 10 * time.Second,
				"record_partitioner": map[string]any{
					"extension": "kafkapartitioner/_agent-component/default",
				},
			},
		},
	}

	for _, testc := range testCases {
		t.Run(testc.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(testc.input)
			require.NoError(t, err, "error creating kafka config")
			gotMap, _, _, err := KafkaToOTelConfig(cfg, "default", logp.NewNopLogger())
			require.NoError(t, err, "error translating kafka to kafka exporter")
			require.Equal(t, testc.expectedMap, gotMap)
		})
	}
}

func TestDynamicTopicSetter(t *testing.T) {
	testCases := []struct {
		name                 string
		topic                string
		expectedTransformMap map[string]any
		err                  error
	}{
		{
			name:  "test where topic=field",
			topic: `%{[data_stream.type]}`,
			expectedTransformMap: map[string]any{
				"transform/_agent-component/default": map[string]any{
					"error_mode": "ignore",
					"log_statements": []string{
						`set(resource.attributes["topic"], log.body["data_stream"]["type"])`,
					},
				}},
			err: nil,
		},
		{
			name:  "test correct behavior when two keys are same",
			topic: `%{[data_stream.type]}-%{[data_stream.type]}`,
			expectedTransformMap: map[string]any{
				"transform/_agent-component/default": map[string]any{
					"error_mode": "ignore",
					"log_statements": []string{
						`set(resource.attributes["topic"], log.body["data_stream"]["type"])`,
						`set(resource.attributes["topic"], Concat([resource.attributes["topic"], log.body["data_stream"]["type"]], "-"))`,
					},
				}},
			err: nil,
		},
		{
			name:  "test where topic = topic + field",
			topic: `%{[data_stream.type]}-%{[data_stream.dataset]}-%{[data_stream.namespace]}`,
			expectedTransformMap: map[string]any{
				"transform/_agent-component/default": map[string]any{
					"error_mode": "ignore",
					"log_statements": []string{
						`set(resource.attributes["topic"], log.body["data_stream"]["type"])`,
						`set(resource.attributes["topic"], Concat([resource.attributes["topic"], log.body["data_stream"]["dataset"]], "-"))`,
						`set(resource.attributes["topic"], Concat([resource.attributes["topic"], log.body["data_stream"]["namespace"]], "-"))`,
					},
				}},
			err: nil,
		},
		{
			name:  "test where topic = literal + field ",
			topic: `test-data-%{[data_stream.dataset]}-%{[data_stream.namespace]}`,
			expectedTransformMap: map[string]any{
				"transform/_agent-component/default": map[string]any{
					"error_mode": "ignore",
					"log_statements": []string{
						`set(resource.attributes["topic"], Concat(["test-data-", log.body["data_stream"]["dataset"]], ""))`,
						`set(resource.attributes["topic"], Concat([resource.attributes["topic"], log.body["data_stream"]["namespace"]], "-"))`,
					},
				}},
			err: nil,
		},
		{
			name:  "test where topic =  topic + literal + field ",
			topic: `%{[data_stream.dataset]}-test-data-%{[data_stream.namespace]}`,
			expectedTransformMap: map[string]any{
				"transform/_agent-component/default": map[string]any{
					"error_mode": "ignore",
					"log_statements": []string{
						`set(resource.attributes["topic"], log.body["data_stream"]["dataset"])`,
						`set(resource.attributes["topic"], Concat([resource.attributes["topic"], log.body["data_stream"]["namespace"]], "-test-data-"))`,
					},
				}},
			err: nil,
		},
		{
			name:  "test where topic =  field + literal (i.e any content left is appended to final topic string) ",
			topic: `%{[data_stream.dataset]}-test-data`,
			expectedTransformMap: map[string]any{
				"transform/_agent-component/default": map[string]any{
					"error_mode": "ignore",
					"log_statements": []string{
						`set(resource.attributes["topic"], log.body["data_stream"]["dataset"])`,
						`set(resource.attributes["topic"], Concat([resource.attributes["topic"], "-test-data"], ""))`,
					},
				}},
			err: nil,
		},
		{
			name:                 "return error if closing bracket not found",
			topic:                `%{[data_stream.dataset]-no-closing-bracket`,
			expectedTransformMap: nil,
			err:                  fmt.Errorf("missing closing '}'"),
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			_, err := fmtstr.CompileEvent(test.topic)
			if test.err != nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			processor, err := dynamicTopicSetterProcessor(test.topic, "default")
			require.NoError(t, err)
			require.Equal(t, test.expectedTransformMap, processor)
		})
	}
}

func TestGetOauth2ClientExtensionConfig(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		outputName     string
		expectedFields map[string]any
		expectedErrMsg string
	}{
		{
			name: "success with required fields",
			input: `
client_id: my-client
client_secret: my-secret
token_url: https://example.com/oauth2/token
`,
			outputName: "default",
			expectedFields: map[string]any{
				"client_id":     "my-client",
				"client_secret": configopaque.String("my-secret"),
				"token_url":     "https://example.com/oauth2/token",
				"expiry_buffer": 5 * time.Minute,
			},
		},
		{
			name: "success with optional scopes",
			input: `
client_id: my-client
client_secret: my-secret
token_url: https://example.com/oauth2/token
scopes: ["kafka", "openid"]
`,
			outputName: "monitoring",
			expectedFields: map[string]any{
				"client_id":     "my-client",
				"client_secret": configopaque.String("my-secret"),
				"token_url":     "https://example.com/oauth2/token",
				"scopes":        []string{"kafka", "openid"},
				"expiry_buffer": 5 * time.Minute,
			},
		},
		{
			name: "error when client_id is missing",
			input: `
client_secret: my-secret
token_url: https://example.com/oauth2/token
`,
			outputName:     "default",
			expectedErrMsg: "no ClientID provided",
		},
		{
			name: "error when client_secret is missing",
			input: `
client_id: my-client
token_url: https://example.com/oauth2/token
`,
			outputName:     "default",
			expectedErrMsg: "no ClientSecret provided",
		},
		{
			name: "error when token_url is missing",
			input: `
client_id: my-client
client_secret: my-secret
`,
			outputName:     "default",
			expectedErrMsg: "no TokenURL provided",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(tc.input)
			require.NoError(t, err)

			got, err := getOauth2ClientExtensionConfig(cfg, tc.outputName)
			if tc.expectedErrMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedErrMsg)
				require.Nil(t, got)
				return
			}

			require.NoError(t, err)
			extensionID := fmt.Sprintf("oauth2client/_agent-component/%s", tc.outputName)
			require.Contains(t, got, extensionID)
			gotCfg := got[extensionID].(map[string]any)
			for key, want := range tc.expectedFields {
				require.Equal(t, want, gotCfg[key], "field %s", key)
			}
		})
	}
}

func TestUnsupportedParams(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{
			"ca_trusted_fingerprint is set",
			`
hosts: ["kafka1:9092", "kafka2:9092", "kafka3:9092"]
topic: static-topic
ssl:
  ca_trusted_fingerprint:  fingerprint
`,
		},
		{
			"ca_sha_256 is set",
			`
hosts: ["kafka1:9092", "kafka2:9092", "kafka3:9092"]
topic: static-topic
ssl:
  ca_sha_256:  sha256
`,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(test.input)
			require.NoError(t, err)
			_, _, _, err = KafkaToOTelConfig(cfg, "", logp.NewNopLogger())
			require.ErrorIs(t, err, errors.ErrUnsupported)
		})
	}
}
