// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/component"
)

const (
	// ContentTypeDirectory should be used to indicate that a directory should be made in the resulting bundle
	ContentTypeDirectory = "directory"
	// REDACTED is used to replace sensative fields
	REDACTED  = "<REDACTED>"
	agentName = "elastic-agent"
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

// CreateCPUProfile will gather a CPU profile over a given time duration.
func CreateCPUProfile(ctx context.Context, period time.Duration) ([]byte, error) {
	var writeBuf bytes.Buffer
	err := pprof.StartCPUProfile(&writeBuf)
	if err != nil {
		return nil, fmt.Errorf("error starting CPU profile: %w", err)
	}
	tc := time.After(period)
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("Got context done")
	case <-tc:
		break
	}

	pprof.StopCPUProfile()
	return writeBuf.Bytes(), nil
}

// ZipArchive creates a zipped diagnostics bundle using the passed writer with the passed diagnostics and local logs.
// If any error is encountered when writing the contents of the archive it is returned.
func ZipArchive(errOut, w io.Writer, agentDiag []client.DiagnosticFileResult, unitDiags []client.DiagnosticUnitResult, compDiags []client.DiagnosticComponentResult) error {
	ts := time.Now().UTC()
	zw := zip.NewWriter(w)
	defer zw.Close()
	log := logp.L()
	// Write agent diagnostics content
	for _, ad := range agentDiag {
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

	// Handle unit diagnostics
	// structure each unit into its own component directory
	compDirs := make(map[string][]client.DiagnosticUnitResult)
	for _, ud := range unitDiags {
		compDir := strings.ReplaceAll(ud.ComponentID, "/", "-")
		compDirs[compDir] = append(compDirs[compDir], ud)
	}

	componentResults := map[string]client.DiagnosticComponentResult{}
	// handle component diagnostics
	for _, comp := range compDiags {
		compDir := strings.ReplaceAll(comp.ComponentID, "/", "-")
		componentResults[compDir] = comp
	}
	// write each units diagnostics into its own directory
	// layout becomes components/<component-id>/<unit-id>/<filename>
	_, err := zw.CreateHeader(&zip.FileHeader{
		Name:     "components/",
		Method:   zip.Deflate,
		Modified: ts,
	})
	if err != nil {
		return fmt.Errorf("error creating .zip header for components/ directory: %w", err)
	}
	// iterate over components
	for dirName, units := range compDirs {
		_, err := zw.CreateHeader(&zip.FileHeader{
			Name:     fmt.Sprintf("components/%s/", dirName),
			Method:   zip.Deflate,
			Modified: ts,
		})
		if err != nil {
			return fmt.Errorf("error creating .zip header for component directory: %w", err)
		}
		// create component diags
		if comp, ok := componentResults[dirName]; ok {
			// check for component-level errors
			if comp.Err != nil {
				w, err := zw.CreateHeader(&zip.FileHeader{
					Name:     fmt.Sprintf("components/%s/error.txt", dirName),
					Method:   zip.Deflate,
					Modified: ts,
				})
				if err != nil {
					return fmt.Errorf("error writing header for error.txt file for component %s: %s", comp.ComponentID, err)
				}
				_, err = w.Write([]byte(fmt.Sprintf("%s\n", comp.Err)))
				if err != nil {
					return fmt.Errorf("error writing error.txt file for component %s: %s", comp.ComponentID, err)
				}

			} else {
				for _, res := range comp.Results {

					filePath := fmt.Sprintf("components/%s/%s", dirName, res.Filename)
					log.Infof("creating component diag directory at %s", filePath)
					resFileWriter, err := zw.CreateHeader(&zip.FileHeader{
						Name:     filePath,
						Method:   zip.Deflate,
						Modified: ts,
					})
					if err != nil {
						return fmt.Errorf("error creating .zip header for %s: %w", res.Filename, err)
					}
					err = writeRedacted(errOut, resFileWriter, filePath, res)
					if err != nil {
						return fmt.Errorf("error writing %s in zip file: %w", res.Filename, err)
					}
				}
			}

		}
		// create unit diags
		for _, ud := range units {
			unitDir := strings.ReplaceAll(strings.TrimPrefix(ud.UnitID, ud.ComponentID+"-"), "/", "-")
			_, err := zw.CreateHeader(&zip.FileHeader{
				Name:     fmt.Sprintf("components/%s/%s/", dirName, unitDir),
				Method:   zip.Deflate,
				Modified: ts,
			})
			if err != nil {
				return fmt.Errorf("error creating .zip header for unit directory: %w", err)
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
				filePath := fmt.Sprintf("components/%s/%s/%s", dirName, unitDir, fr.Filename)
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

	// Gather Logs:
	return zipLogs(zw, ts)
}

func writeRedacted(errOut, w io.Writer, fullFilePath string, fr client.DiagnosticFileResult) error {
	out := &fr.Content

	// Should we support json too?
	if fr.ContentType == "application/yaml" {
		unmarshalled := map[interface{}]interface{}{}
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

func redactMap(m map[interface{}]interface{}) map[interface{}]interface{} {
	for k, v := range m {
		if v != nil && reflect.TypeOf(v).Kind() == reflect.Map {
			v = redactMap(v.(map[interface{}]interface{}))
		}
		if s, ok := k.(string); ok {
			if redactKey(s) {
				v = REDACTED
			}
			m[k] = v
		}
	}
	return m
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

func zipLogs(zw *zip.Writer, ts time.Time) error {
	currentDir := fmt.Sprintf("%s-%s", agentName, release.ShortCommit())
	if !paths.IsVersionHome() {
		// running in a container with custom top path set
		// logs are directly under top path
		return zipLogsWithPath(paths.Home(), currentDir, true, zw, ts)
	}

	dataDir, err := os.Open(paths.Data())
	if err != nil {
		return err
	}
	defer dataDir.Close()

	subdirs, err := dataDir.Readdirnames(0)
	if err != nil {
		return err
	}

	dirPrefix := fmt.Sprintf("%s-", agentName)
	for _, dir := range subdirs {
		if !strings.HasPrefix(dir, dirPrefix) {
			continue
		}
		collectServices := dir == currentDir
		path := filepath.Join(paths.Data(), dir)
		if err := zipLogsWithPath(path, dir, collectServices, zw, ts); err != nil {
			return err
		}
	}

	return nil
}

// zipLogs walks paths.Logs() and copies the file structure into zw in "logs/"
func zipLogsWithPath(pathsHome, commitName string, collectServices bool, zw *zip.Writer, ts time.Time) error {
	_, err := zw.CreateHeader(&zip.FileHeader{
		Name:     "logs/",
		Method:   zip.Deflate,
		Modified: ts,
	})
	if err != nil {
		return err
	}

	if collectServices {
		if err := collectServiceComponentsLogs(zw); err != nil {
			return fmt.Errorf("failed to collect endpoint-security logs: %w", err)
		}
	}

	_, err = zw.CreateHeader(&zip.FileHeader{
		Name:     "logs/" + commitName + "/",
		Method:   zip.Deflate,
		Modified: ts,
	})
	if err != nil {
		return err
	}

	// using Data() + "/logs", for some reason default paths/Logs() is the home dir...
	logPath := filepath.Join(pathsHome, "logs") + string(filepath.Separator)
	return filepath.WalkDir(logPath, func(path string, d fs.DirEntry, fErr error) error {
		if errors.Is(fErr, fs.ErrNotExist) {
			return nil
		}
		if fErr != nil {
			return fmt.Errorf("unable to walk log dir: %w", fErr)
		}

		// name is the relative dir/file name replacing any filepath seperators with /
		// this will clean log names on windows machines and will nop on *nix
		name := filepath.ToSlash(strings.TrimPrefix(path, logPath))
		if name == "" {
			return nil
		}

		name = filepath.Join(commitName, name)

		if d.IsDir() {
			_, err := zw.CreateHeader(&zip.FileHeader{
				Name:     "logs/" + filepath.ToSlash(name) + "/",
				Method:   zip.Deflate,
				Modified: ts,
			})
			if err != nil {
				return fmt.Errorf("unable to create log directory in archive: %w", err)
			}
			return nil
		}

		return saveLogs(name, path, zw)
	})
}

func collectServiceComponentsLogs(zw *zip.Writer) error {
	platform, err := component.LoadPlatformDetail()
	if err != nil {
		return fmt.Errorf("failed to gather system information: %w", err)
	}
	specs, err := component.LoadRuntimeSpecs(paths.Components(), platform)
	if err != nil {
		return fmt.Errorf("failed to detect inputs and outputs: %w", err)
	}
	for _, spec := range specs.ServiceSpecs() {
		if spec.Spec.Service.Log == nil || spec.Spec.Service.Log.Path == "" {
			// no log path set in specification
			continue
		}

		logPath := filepath.Dir(spec.Spec.Service.Log.Path) + string(filepath.Separator)
		err = filepath.WalkDir(logPath, func(path string, d fs.DirEntry, fErr error) error {
			if fErr != nil {
				if errors.Is(fErr, fs.ErrNotExist) {
					return nil
				}

				return fmt.Errorf("unable to walk log directory %q for service input %s: %w", logPath, spec.InputType, fErr)
			}

			name := filepath.ToSlash(strings.TrimPrefix(path, logPath))
			if name == "" {
				return nil
			}

			if d.IsDir() {
				return nil
			}

			return saveLogs("services/"+name, path, zw)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func saveLogs(name string, logPath string, zw *zip.Writer) error {
	ts := time.Now().UTC()
	lf, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("unable to open log file: %w", err)
	}
	defer lf.Close()
	if li, err := lf.Stat(); err == nil {
		ts = li.ModTime()
	}
	zf, err := zw.CreateHeader(&zip.FileHeader{
		Name:     "logs/" + filepath.ToSlash(name),
		Method:   zip.Deflate,
		Modified: ts,
	})
	if err != nil {
		return err
	}
	_, err = io.Copy(zf, lf)
	if err != nil {
		return err
	}

	return nil
}
