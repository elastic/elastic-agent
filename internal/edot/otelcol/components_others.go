// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

<<<<<<<< HEAD:internal/pkg/agent/cmd/run_unix.go
package cmd
========
package otelcol
>>>>>>>> c1777a5ce (feat: move edot in a separate package (#10922)):internal/edot/otelcol/components_others.go

// logExternal logs the error to an external log.  On non-windows systems this is a no-op.
func logExternal(msg string) {
}
