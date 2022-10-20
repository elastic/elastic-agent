// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"runtime/pprof"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/control/client"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

// ContentTypeDirectory should be used to indicate that a directory should be made in the resulting bundle
const ContentTypeDirectory = "directory"

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

// ZipArchive creates a zipped diagnostics bundle using the passed writer with the passed diagnostics.
// If any error is encounted when writing the contents of the archive it is returned.
func ZipArchive(w io.Writer, agentDiag []client.DiagnosticFileResult, unitDiags []client.DiagnosticUnitResult) error {
	zw := zip.NewWriter(w)
	defer zw.Close()
	// Create directories in the zip archive before writing any files
	for _, ad := range agentDiag {
		if ad.ContentType == ContentTypeDirectory {
			_, err := zw.Create(ad.Filename)
			if err != nil {
				return err
			}
		}
	}
	// Write agent diagnostics content
	// TODO timestamps for log files
	for _, ad := range agentDiag {
		if ad.ContentType != ContentTypeDirectory {
			zf, err := zw.Create(ad.Filename)
			if err != nil {
				return err
			}
			_, err = zf.Write(ad.Content)
			if err != nil {
				return err
			}
		}
	}

	// Handle unit diagnostics
	// structure each unit into its own component directory
	compDirs := make(map[string][]client.DiagnosticUnitResult)
	for _, ud := range unitDiags {
		compDir := strings.ReplaceAll(ud.ComponentID, "/", "-")
		compDirs[compDir] = append(compDirs[compDir], ud)
	}
	// write each units diagnostics into its own directory
	// layout becomes components/<component-id>/<unit-id>/<filename>
	_, err := zw.Create("components/")
	if err != nil {
		return err
	}
	for dirName, units := range compDirs {
		_, err = zw.Create(fmt.Sprintf("components/%s/", dirName))
		if err != nil {
			return err
		}
		for _, ud := range units {
			unitDir := strings.ReplaceAll(strings.TrimPrefix(ud.UnitID, ud.ComponentID+"-"), "/", "-")
			_, err = zw.Create(fmt.Sprintf("components/%s/%s/", dirName, unitDir))
			if err != nil {
				return err
			}
			if ud.Err != nil {
				w, err := zw.Create(fmt.Sprintf("components/%s/%s/error.txt", dirName, unitDir))
				if err != nil {
					return err
				}
				_, err = w.Write([]byte(fmt.Sprintf("%s\n", ud.Err)))
				if err != nil {
					return err
				}
				continue
			}
			for _, fr := range ud.Results {
				w, err := zw.Create(fmt.Sprintf("components/%s/%s/%s", dirName, unitDir, fr.Name))
				if err != nil {
					return err
				}
				_, err = w.Write(fr.Content)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
