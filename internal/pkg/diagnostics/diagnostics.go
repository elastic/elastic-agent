// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/go-ucfg"

	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/version"
)

const (
	// ContentTypeDirectory should be used to indicate that a directory should be made in the resulting bundle
	ContentTypeDirectory = "directory"
	// REDACTED is used to replace sensative fields
	REDACTED  = "<REDACTED>"
	agentName = "elastic-agent"
)

// DiagCPU* are contstants to describe the CPU profile that is collected when the --cpu-profile flag is used with the diagnostics command, or the diagnostics action contains "CPU" in the additional_metrics list.
const (
	DiagCPUName        = "cpuprofile"
	DiagCPUFilename    = "cpu.pprof"
	DiagCPUDescription = "CPU profile"
	DiagCPUContentType = "application/octet-stream"
	DiagCPUDuration    = 30 * time.Second
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
			Name:        "package version",
			Filename:    "package.version",
			Description: "Package Version",
			ContentType: "text/plain",
			Hook: func(_ context.Context) []byte {
				pkgVersionPath, err := version.GetAgentPackageVersionFilePath()
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				fileBytes, err := os.ReadFile(pkgVersionPath)
				if err != nil {
					return []byte(fmt.Sprintf("error: %q", err))
				}
				return fileBytes
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
			Filename:    "block.pprof.gz",
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
		pprof.StopCPUProfile()
		return nil, ctx.Err()
	case <-tc:
		break
	}

	pprof.StopCPUProfile()
	return writeBuf.Bytes(), nil
}

// ZipArchive creates a zipped diagnostics bundle using the passed writer with the passed diagnostics and local logs.
// If any error is encountered when writing the contents of the archive it is returned.
func ZipArchive(
	errOut,
	w io.Writer,
	topPath string,
	agentDiag []client.DiagnosticFileResult,
	unitDiags []client.DiagnosticUnitResult,
	compDiags []client.DiagnosticComponentResult,
	excludeEvents bool) error {

	ts := time.Now().UTC()
	zw := zip.NewWriter(w)
	defer zw.Close()
	// Write agent diagnostics content
	for _, ad := range agentDiag {
		zf, err := zw.CreateHeader(&zip.FileHeader{
			Name:     ad.Filename,
			Method:   zip.Deflate,
			Modified: ad.Generated,
		})
		if err != nil {
			return fmt.Errorf("error creating header for agent diagnostics: %w", err)
		}
		err = writeRedacted(errOut, zf, ad.Filename, ad)
		if err != nil {
			return fmt.Errorf("error writing file for agent diagnostics: %w", err)
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
				err = writeErrorResult(zw, fmt.Sprintf("components/%s/error.txt", dirName), comp.Err.Error())
				if err != nil {
					return fmt.Errorf("error while writing error result for component %s: %w", comp.ComponentID, err)
				}
			} else {
				for _, res := range comp.Results {

					filePath := fmt.Sprintf("components/%s/%s", dirName, res.Filename)
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
			// check for unit-level errors
			if ud.Err != nil {
				err = writeErrorResult(zw, fmt.Sprintf("components/%s/%s/error.txt", dirName, unitDir), ud.Err.Error())
				if err != nil {
					return fmt.Errorf("error while writing error result for unit %s: %w", ud.UnitID, err)
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
	return zipLogs(zw, ts, topPath, excludeEvents)
}

func writeErrorResult(zw *zip.Writer, path string, errBody string) error {
	ts := time.Now().UTC()
	w, err := zw.CreateHeader(&zip.FileHeader{
		Name:     path,
		Method:   zip.Deflate,
		Modified: ts,
	})
	if err != nil {
		return fmt.Errorf("error writing header for error.txt file for component: %w", err)
	}
	_, err = w.Write([]byte(fmt.Sprintf("%s\n", errBody)))
	if err != nil {
		return fmt.Errorf("error writing error.txt file for component: %w", err)
	}

	return nil
}

func writeRedacted(errOut, resultWriter io.Writer, fullFilePath string, fileResult client.DiagnosticFileResult) error {
	out := &fileResult.Content

	// Should we support json too?
	if fileResult.ContentType == "application/yaml" {
		unmarshalled := map[string]interface{}{}
		err := yaml.Unmarshal(fileResult.Content, &unmarshalled)
		if err != nil {
			// Best effort, output a warning but still include the file
			fmt.Fprintf(errOut, "[WARNING] Could not redact %s due to unmarshalling error: %s\n", fullFilePath, err)
		} else {
			unmarshalled = RedactSecretPaths(unmarshalled, errOut)
			redacted, err := yaml.Marshal(redactMap(errOut, unmarshalled))
			if err != nil {
				// Best effort, output a warning but still include the file
				fmt.Fprintf(errOut, "[WARNING] Could not redact %s due to marshalling error: %s\n", fullFilePath, err)
			} else {
				out = &redacted
			}
		}
	}

	_, err := resultWriter.Write(*out)
	return err
}

// redactMap sensitive values from the underlying map
// the whole generic function here is out of paranoia. Although extremely unlikely,
// we have no way of guaranteeing we'll get a "normal" map[string]interface{},
// since the diagnostic interface is a bit of a free-for-all
func redactMap[K comparable](errOut io.Writer, inputMap map[K]interface{}) map[K]interface{} {
	if inputMap == nil {
		return nil
	}
	for rootKey, rootValue := range inputMap {
		if rootValue != nil {
			switch cast := rootValue.(type) {
			case map[string]interface{}:
				rootValue = redactMap(errOut, cast)
			case map[interface{}]interface{}:
				rootValue = redactMap(errOut, cast)
			case map[int]interface{}:
				rootValue = redactMap(errOut, cast)
			case string:
				if keyString, ok := any(rootKey).(string); ok {
					if redactKey(keyString) {
						rootValue = REDACTED
					}
				}
			default:
				// in cases where we got some weird kind of map we couldn't parse, print a warning
				if reflect.TypeOf(rootValue).Kind() == reflect.Map {
					fmt.Fprintf(errOut, "[WARNING]: file may be partly redacted, could not cast value %v of type %T", rootKey, rootValue)
				}

			}
		}

		inputMap[rootKey] = rootValue

	}
	return inputMap
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

func zipLogs(zw *zip.Writer, ts time.Time, topPath string, excludeEvents bool) error {
	homePath := paths.HomeFrom(topPath)
	dataPath := paths.DataFrom(topPath)
	currentDir := filepath.Base(homePath)
	if !paths.IsVersionHome() {
		// running in a container with custom top path set
		// logs are directly under top path
		return zipLogsWithPath(homePath, currentDir, true, excludeEvents, zw, ts)
	}

	dataDir, err := os.Open(dataPath)
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
		path := filepath.Join(dataPath, dir)
		if err := zipLogsWithPath(path, dir, collectServices, excludeEvents, zw, ts); err != nil {
			return err
		}
	}

	return nil
}

// zipLogs walks paths.Logs() and copies the file structure into zw in "logs/"
func zipLogsWithPath(pathsHome, commitName string, collectServices, excludeEvents bool, zw *zip.Writer, ts time.Time) error {
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

		// Skip events logs, if necessary
		// name can either be the folder name 'events' or the folder plus
		// the file name like 'events/elastic-agent-events-log.ndjson'
		// we need to skip both.
		if excludeEvents && strings.HasPrefix(name, "events") {
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

// RedactSecretPaths will check the passed mapStr input for a secret_paths attribute.
// If found it will replace the value for every key in the paths list with <REDACTED> and return the resulting map.
// Any issues or errors will be written to the errOut writer.
func RedactSecretPaths(mapStr map[string]any, errOut io.Writer) map[string]any {
	v, ok := mapStr["secret_paths"]
	if !ok {
		return mapStr
	}
	arr, ok := v.([]interface{})
	if !ok {
		fmt.Fprintln(errOut, "No output redaction: secret_paths attribute is not a list.")
		return mapStr
	}
	cfg := ucfg.MustNewFrom(mapStr)
	for _, v := range arr {
		key, ok := v.(string)
		if !ok {
			fmt.Fprintf(errOut, "No output redaction for %q: expected type string, is type %T.\n", v, v)
			continue
		}

		if ok, _ := cfg.Has(key, -1, ucfg.PathSep(".")); ok {
			err := cfg.SetString(key, -1, REDACTED, ucfg.PathSep("."))
			if err != nil {
				fmt.Fprintf(errOut, "No output redaction for %q: %v.\n", key, err)
			}
		}
	}
	result, err := config.MustNewConfigFrom(cfg).ToMapStr()
	if err != nil {
		return mapStr
	}
	return result
}
