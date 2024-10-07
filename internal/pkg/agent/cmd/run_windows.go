// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package cmd

import (
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

// logExternal logs the error to an external log.  On Windows this is
// the Application EventLog.  This is a best effort logger and no
// errors are returned.
func logExternal(msg string) {
	eLog, err2 := eventlog.Open(paths.ServiceName())
	if err2 != nil {
		return
	}
	_ = eLog.Error(1, msg)
}
