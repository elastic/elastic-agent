// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package iocprepro contains a minimal, self-contained test that reproduces a
// Windows-only Go runtime crash:
//
//	runtime: marked free object in span ..., elemsize=N freeindex=...
//	fatal error: found pointer to free object
//
// The crash fires when a tight burst of Windows filesystem syscalls
// (MkdirAll, WriteFile, Symlink, marker-file marshal+write) runs concurrently
// with Go's GC. The pattern is taken directly from this repository's upgrade
// rollback test setupAgents helper, which reproduces the bug reliably on
// Buildkite's Azure D8s_v5 Windows 11 runners under GOGC=1 + -race +
// clobberfree + gccheckmark + asyncpreemptoff + cgocheck2, but does not
// reproduce on most local Windows machines.
//
// The intent is for this package to depend on nothing but the Go standard
// library so that, once a fatal-panic dump is captured, the test function
// can be lifted verbatim into a golang/go issue without dragging in any
// elastic-agent infrastructure.
//
// Related upstream issue: https://github.com/golang/go/issues/77975
package iocprepro
