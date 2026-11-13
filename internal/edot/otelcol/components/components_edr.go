// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build edr

package components

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	abreceiver "github.com/elastic/beats/v7/x-pack/auditbeat/abreceiver"

	"go.opentelemetry.io/collector/receiver"
)

// addFullBeatReceivers adds the auditbeat receiver (Auditd Manager and File
// Integrity Monitoring) for the EDR flavor build. The heartbeat
// receiver is intentionally excluded.
func addFullBeatReceivers(receivers []receiver.Factory) []receiver.Factory {
	return append(receivers,
		abreceiver.NewFactoryWithSettings(abreceiver.Settings{Home: paths.Components(), Data: paths.Data()}),
	)
}
