// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package upgrade

import winSys "golang.org/x/sys/windows"

var TestErrors = []error{
	winSys.ERROR_DISK_FULL,
	winSys.ERROR_HANDLE_DISK_FULL,
}
