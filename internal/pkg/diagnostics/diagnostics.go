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
	"reflect"
	"runtime/pprof"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/control/v2/client"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

const (
	// ContentTypeDirectory should be used to indicate that a directory should be made in the resulting bundle
	ContentTypeDirectory = "directory"
	// REDACTED is used to replace sensative fields
	REDACTED = "<REDACTED>"
)

// Hook is a hook that gets used when diagnostic information is requested from the Elastic Agent.
type Hook struct {
	Name        string
	Filename    string
	Description string
	ContentType string
	Hook        func(ctx context.Context) ([]byte, time.Time)
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
			Hook: func(_ context.Context) ([]byte, time.Time) {
				v := release.Info()
				o, err := yaml.Marshal(v)
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err)), time.Now().UTC()
				}
				return o, time.Now().UTC()
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

func pprofDiag(name string) func(context.Context) ([]byte, time.Time) {
	return func(_ context.Context) ([]byte, time.Time) {
		var w bytes.Buffer
		err := pprof.Lookup(name).WriteTo(&w, 1)
		if err != nil {
			// error is returned as the content
			return []byte(fmt.Sprintf("failed to write pprof to bytes buffer: %s", err)), time.Now().UTC()
		}
		return w.Bytes(), time.Now().UTC()
	}
}

// ZipArchive creates a zipped diagnostics bundle using the passed writer with the passed diagnostics.
// If any error is encountered when writing the contents of the archive it is returned.
func ZipArchive(errOut, w io.Writer, agentDiag []client.DiagnosticFileResult, unitDiags []client.DiagnosticUnitResult) error {
	ts := time.Now().UTC()
	zw := zip.NewWriter(w)
	defer zw.Close()
	// Create directories in the zip archive before writing any files
	for _, ad := range agentDiag {
		if ad.ContentType == ContentTypeDirectory {
			_, err := zw.CreateHeader(&zip.FileHeader{
				Name:     ad.Filename,
				Method:   zip.Deflate,
				Modified: ts,
			})
			if err != nil {
				return err
			}
		}
	}
	// Write agent diagnostics content
	for _, ad := range agentDiag {
		if ad.ContentType != ContentTypeDirectory {
			zf, err := zw.CreateHeader(&zip.FileHeader{
				Name:     ad.Filename,
				Method:   zip.Deflate,
				Modified: ad.Generated,
			})
			if err != nil {
				return err
			}
			err = writeRedacted(errOut, zf, ad.Filename, ad)
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
	_, err := zw.CreateHeader(&zip.FileHeader{
		Name:     "components/",
		Method:   zip.Deflate,
		Modified: ts,
	})
	if err != nil {
		return err
	}
	for dirName, units := range compDirs {
		_, err := zw.CreateHeader(&zip.FileHeader{
			Name:     fmt.Sprintf("components/%s/", dirName),
			Method:   zip.Deflate,
			Modified: ts,
		})
		if err != nil {
			return err
		}
		for _, ud := range units {
			unitDir := strings.ReplaceAll(strings.TrimPrefix(ud.UnitID, ud.ComponentID+"-"), "/", "-")
			_, err := zw.CreateHeader(&zip.FileHeader{
				Name:     fmt.Sprintf("components/%s/%s/", dirName, unitDir),
				Method:   zip.Deflate,
				Modified: ts,
			})
			if err != nil {
				return err
			}
			if ud.Err != nil {
				w, err := zw.CreateHeader(&zip.FileHeader{
					Name:     fmt.Sprintf("components/%s/%s/error.txt", dirName, unitDir),
					Method:   zip.Deflate,
					Modified: ts,
				})
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
				filePath := fmt.Sprintf("components/%s/%s/%s", dirName, unitDir, fr.Name)
				w, err := zw.CreateHeader(&zip.FileHeader{
					Name:     filePath,
					Method:   zip.Deflate,
					Modified: fr.Generated,
				})
				if err != nil {
					return err
				}
				err = writeRedacted(errOut, w, filePath, fr)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func writeRedacted(errOut, w io.Writer, fullFilePath string, fr client.DiagnosticFileResult) error {
	out := &fr.Content

	// Should we support json too?
	if fr.ContentType == "application/yaml" {
		unmarshalled := map[string]interface{}{}
		err := yaml.Unmarshal(fr.Content, &unmarshalled)
		if err != nil {
			// Best effort, output a warning but still include the file
			fmt.Fprintf(errOut, "[WARNING] Could not redact %s due to unmarshalling error: %s\n", fullFilePath, err)
		} else {
			redacted, err := yaml.Marshal(redactMap(unmarshalled))
			if err != nil {
				// Best effort, output a warning but still include the file
				fmt.Fprintf(errOut, "[WARNING] Could not redact %s due to marshalling error: %s\n", fullFilePath, err)
			} else {
				out = &redacted
			}
		}
	}

	_, err := w.Write(*out)
	return err
}

func redactMap(m map[string]interface{}) map[string]interface{} {
	for k, v := range m {
		if v != nil && reflect.TypeOf(v).Kind() == reflect.Map {
			v = redactMap(toMapStr(v))
		}
		if redactKey(k) {
			v = REDACTED
		}
		m[k] = v
	}
	return m
}

func toMapStr(v interface{}) map[string]interface{} {
	mm := map[string]interface{}{}
	m, ok := v.(map[interface{}]interface{})
	if !ok {
		return mm
	}

	for k, v := range m {
		mm[k.(string)] = v
	}
	return mm
}

func redactKey(k string) bool {
	// "routekey" shouldn't be redacted.
	// Add any other exceptions here.
	if k == "routekey" {
		return false
	}

	return strings.Contains(k, "certificate") ||
		strings.Contains(k, "passphrase") ||
		strings.Contains(k, "password") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "key")
}
