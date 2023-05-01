// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package diagnostics

import (
	"bytes"
	"context"
	"fmt"
	"runtime/pprof"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/release"
)

// Hook is a hook that gets used when diagnostic information is requested from the Elastic Agent.
type Hook struct {
	Name        string
	Filename    string
	Description string
	ContentType string
	Hook        func(ctx context.Context) []byte
}

// Hooks is a set of diagnostic hooks.
type Hooks []Hook

// GlobalHooks returns the global hooks that can be used at anytime with no other references.
func GlobalHooks() Hooks {
	return Hooks{
		{
			Name:        "version",
			Filename:    "version.txt",
			Description: "version information",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				v := release.Info()
				o, err := yaml.Marshal(v)
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				return o
			},
		},
		{
			Name:        "goroutine",
			Filename:    "goroutine.pprof.gz",
			Description: "stack traces of all current goroutines",
			ContentType: "application/octet-stream",
			Hook:        pprofDiag("goroutine", 0),
		},
		{
			Name:        "heap",
			Filename:    "heap.pprof.gz",
			Description: "a sampling of memory allocations of live objects",
			ContentType: "application/octet-stream",
			Hook:        pprofDiag("heap", 0),
		},
		{
			Name:        "allocs",
			Filename:    "allocs.pprof.gz",
			Description: "a sampling of all past memory allocations",
			ContentType: "application/octet-stream",
			Hook:        pprofDiag("allocs", 0),
		},
		{
			Name:        "threadcreate",
			Filename:    "threadcreate.pprof.gz",
			Description: "stack traces that led to the creation of new OS threads",
			ContentType: "application/octet-stream",
			Hook:        pprofDiag("threadcreate", 0),
		},
		{
			Name:        "block",
			Filename:    "block.pprog.gz",
			Description: "stack traces that led to blocking on synchronization primitives",
			ContentType: "application/octet-stream",
			Hook:        pprofDiag("block", 0),
		},
		{
			Name:        "mutex",
			Filename:    "mutex.pprof.gz",
			Description: "stack traces of holders of contended mutexes",
			ContentType: "application/octet-stream",
			Hook:        pprofDiag("mutex", 0),
		},
	}
}

func pprofDiag(name string, debug int) func(context.Context) []byte {
	return func(_ context.Context) []byte {
		var w bytes.Buffer
		err := pprof.Lookup(name).WriteTo(&w, debug)
		if err != nil {
			// error is returned as the content
			return []byte(fmt.Sprintf("failed to write pprof to bytes buffer: %s", err))
		}
		return w.Bytes()
	}
}
