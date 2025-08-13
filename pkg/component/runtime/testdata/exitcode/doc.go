package main

// This package contains a go program that exits with an exit code.
// The desired exit code must be set at build time using
// go build -ldflags='-X main.ExitCode=<code>'.
// The resulting binary can be used in tests to simulate an
// Agent-managed component, e.g. Endpoint, that exits with a specific
// exit code.
