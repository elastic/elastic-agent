// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package factories

import (
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/otlpreceiver"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

var defaultReceivers = []receiver.Factory{
	filelogreceiver.NewFactory(),
	otlpreceiver.NewFactory(),
	receivertest.NewNopFactory(),
}
