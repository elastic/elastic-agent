// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

const (
	// Elasticsearch represents the elasticsearch output
	Elasticsearch = "elasticsearch"
	// Kafka represents the kafka output
	Kafka = "kafka"
	// Logstash represents the logstash output
	Logstash = "logstash"
	// Redis represents the redis output
	Redis = "redis"
	// Shipper represents support for using the elastic-agent-shipper
	Shipper = "shipper"
)

// Outputs defines the outputs that a component can support
var Outputs = []string{Elasticsearch, Kafka, Logstash, Redis, Shipper}
