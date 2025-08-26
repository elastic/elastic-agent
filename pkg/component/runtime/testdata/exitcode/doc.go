// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

// This package contains a go program that exits with an exit code.
// The desired exit code must be set at build time using
// go build -ldflags='-X main.ExitCode=<code>'.
// The resulting binary can be used in tests to simulate an
// Agent-managed component, e.g. Endpoint, that exits with a specific
// exit code.
