// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package factories

import (
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/connector/forwardconnector"
)

var defaultConnectors = []connector.Factory{
	forwardconnector.NewFactory(),
}
