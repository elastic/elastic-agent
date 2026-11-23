// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package browserca

import "os/exec"

// runAs does nothing: Start manages the browser trust store on Linux only.
func runAs(*exec.Cmd, *owner) {}
