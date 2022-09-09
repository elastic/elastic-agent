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
			Filename:    "goroutine.txt",
			Description: "stack traces of all current goroutines",
			ContentType: "plain/text",
			Hook:        pprofDiag("goroutine"),
		},
		{
			Name:        "heap",
			Filename:    "heap.txt",
			Description: "a sampling of memory allocations of live objects",
			ContentType: "plain/text",
			Hook:        pprofDiag("heap"),
		},
		{
			Name:        "allocs",
			Filename:    "allocs.txt",
			Description: "a sampling of all past memory allocations",
			ContentType: "plain/text",
			Hook:        pprofDiag("allocs"),
		},
		{
			Name:        "threadcreate",
			Filename:    "threadcreate.txt",
			Description: "stack traces that led to the creation of new OS threads",
			ContentType: "plain/text",
			Hook:        pprofDiag("threadcreate"),
		},
		{
			Name:        "block",
			Filename:    "block.txt",
			Description: "stack traces that led to blocking on synchronization primitives",
			ContentType: "plain/text",
			Hook:        pprofDiag("block"),
		},
		{
			Name:        "mutex",
			Filename:    "mutex.txt",
			Description: "stack traces of holders of contended mutexes",
			ContentType: "plain/text",
			Hook:        pprofDiag("mutex"),
		},
	}
}

func pprofDiag(name string) func(context.Context) []byte {
	return func(_ context.Context) []byte {
		var w bytes.Buffer
		err := pprof.Lookup(name).WriteTo(&w, 1)
		if err != nil {
			// error is returned as the content
			return []byte(fmt.Sprintf("failed to write pprof to bytes buffer: %s", err))
		}
		return w.Bytes()
	}
}
