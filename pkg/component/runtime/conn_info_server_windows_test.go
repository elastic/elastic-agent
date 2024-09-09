// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package runtime

import (
	"net"

	"github.com/Microsoft/go-winio"

	"github.com/elastic/elastic-agent-libs/api/npipe"
)

func dialLocal(address string) (net.Conn, error) {
	return winio.DialPipe(npipe.TransformString(address), nil)
}
