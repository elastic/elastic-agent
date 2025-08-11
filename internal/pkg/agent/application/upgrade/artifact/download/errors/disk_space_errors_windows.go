// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package errors

import "golang.org/x/sys/windows"

var OS_DiskSpaceErrors = []error{
	windows.ERROR_DISK_FULL,
	windows.ERROR_HANDLE_DISK_FULL,
}
