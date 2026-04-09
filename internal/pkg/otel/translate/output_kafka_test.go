// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
max_message_bytes: 1000000`,
		expectedMap: map[string]any{
			"brokers": []string{"kafka1:9092", "kafka2:9092", "kafka3:9092"},
			"logs": map[string]any{
				"topic": "static-topic",
			},
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
					"min_size":      0,
					"sizer":         "items",
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
				"brokers": []string{"kafka1:9092", "kafka2:9092", "kafka3:9092"},
				"logs": map[string]any{
					"topic": "static-topic",
				},
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
						"min_size":      0,
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
					"full":             false,
					"refresh_interval": 10 * time.Minute,
					"retry": map[string]any{
						"backoff": 250 * time.Millisecond,
						"max":     3,
					},
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
						"min_size":      0,
					},
					"queue_size": 3200,
				},
				"timeout": 10 * time.Second,
			},
		},
	}

	for _, testc := range testCases {
		t.Run(testc.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(testc.input)
			require.NoError(t, err, "error creating kafka config")
			gotMap, _, err := KafkaToOTelConfig(cfg, "", logp.NewNopLogger())
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
