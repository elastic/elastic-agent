// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !securityonly

package components

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	abreceiver "github.com/elastic/beats/v7/x-pack/auditbeat/abreceiver"
	hbreceiver "github.com/elastic/beats/v7/x-pack/heartbeat/hbreceiver"

	"go.opentelemetry.io/collector/receiver"
)

// addFullBeatReceivers registers the auditbeat and heartbeat receivers, which
// are present in all non-security-only EDOT builds.
func addFullBeatReceivers(receivers []receiver.Factory) []receiver.Factory {
	return append(receivers,
		abreceiver.NewFactoryWithSettings(abreceiver.Settings{Home: paths.Components(), Data: paths.Data()}),
		hbreceiver.NewFactoryWithSettings(hbreceiver.Settings{Home: paths.Components(), Data: paths.Data()}),
	)
}
