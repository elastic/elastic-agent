// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux
// +build linux

package otel

import (
	"go.opentelemetry.io/collector/receiver"
	profilingreceiver "go.opentelemetry.io/ebpf-profiler/collector"
)

func addOsSpecificReceivers(receivers []receiver.Factory) []receiver.Factory {

	receivers = append(receivers,
		profilingreceiver.NewFactory())

	return receivers

}
