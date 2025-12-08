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
	"github.com/elastic/elastic-agent/pkg/core/logger"
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
			Name:        "environment",
			Filename:    "environment.yaml",
			Description: "Environment variables",
			ContentType: "application/yaml",
			Hook: func(_ context.Context) []byte {
				redacted, err := redactEnv()
				if err != nil {
					return []byte(err.Error())
				}
				out, err := yaml.Marshal(redacted)
				if err != nil {
					return []byte(fmt.Sprintf("Unable to marshall env vars into yaml: %v", err))
				}
				return out
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
	for dirName, comp := range componentResults {
		_, err := zw.CreateHeader(&zip.FileHeader{
			Name:     fmt.Sprintf("components/%s/", dirName),
			Method:   zip.Deflate,
			Modified: ts,
		})
		if err != nil {
			return fmt.Errorf("error creating .zip header for component directory: %w", err)
		}
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
		// create unit diags
		if units, ok := compDirs[dirName]; ok {
			// check for component-level errors
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
	_, err = fmt.Fprintf(w, "%s\n", errBody)
	if err != nil {
		return fmt.Errorf("error writing error.txt file for component: %w", err)
	}

	return nil
}

func writeRedacted(errOut, resultWriter io.Writer, fullFilePath string, fileResult client.DiagnosticFileResult) error {
	out := &fileResult.Content

	// Should we support json too?
	if fileResult.ContentType == "application/yaml" {
		var unmarshalled any
		err := yaml.Unmarshal(fileResult.Content, &unmarshalled)
		if err != nil {
			// Best effort, output a warning but still include the file
			fmt.Fprintf(errOut, "[WARNING] Could not redact %s due to unmarshalling error: %s\n", fullFilePath, err)
		} else {
			switch t := unmarshalled.(type) { // could be a plain string, we only redact if this is a proper map
			case map[string]any:
				t = Redact(t, errOut)
				redacted, err := yaml.Marshal(t)
				if err != nil {
					// Best effort, output a warning but still include the file
					fmt.Fprintf(errOut, "[WARNING] Could not redact %s due to marshalling error: %s\n", fullFilePath, err)
				} else {
					out = &redacted
				}
			default:
			}
		}
	}

	_, err := resultWriter.Write(*out)
	return err
}

const redactionMarkerPrefix = "__mark_redact_"

// redactMap sensitive values from the underlying map
// the whole generic function here is out of paranoia. Although extremely unlikely,
// we have no way of guaranteeing we'll get a "normal" map[string]interface{},
// since the diagnostic interface is a bit of a free-for-all
func redactMap[K comparable](errOut io.Writer, inputMap map[K]interface{}, sliceElem bool) map[K]interface{} {
	if inputMap == nil {
		return nil
	}

	redactionMarkers := []string{}
	for rootKey, rootValue := range inputMap {
		if rootValue != nil {
			switch cast := rootValue.(type) {
			case map[string]interface{}:
				rootValue = redactMap(errOut, cast, false)
			case map[interface{}]interface{}:
				rootValue = redactMap(errOut, cast, false)
			case map[int]interface{}:
				rootValue = redactMap(errOut, cast, false)
			case []interface{}:
				// Recursively process each element in the slice so that we also walk
				// through lists (e.g. inputs[4].streams[0]). This is required to
				// reach redaction markers that are inside slice items. Set SliceElem to true
				// to avoid global redaction of slice elements.
				for i, value := range cast {
					switch m := value.(type) {
					case map[string]interface{}:
						cast[i] = redactMap(errOut, m, true)
					case map[interface{}]interface{}:
						cast[i] = redactMap(errOut, m, true)
					case map[int]interface{}:
						cast[i] = redactMap(errOut, m, true)
					}
				}
				rootValue = cast
			case string:
				if keyString, ok := any(rootKey).(string); ok {
					// Avoid global redaction of slice elements.
					if redactKey(keyString) && !sliceElem {
						rootValue = REDACTED
					}
				}
			case bool: // redaction marker values are always going to be bool, process redaction markers in this case
				if keyString, ok := any(rootKey).(string); ok {
					// Find siblings that have the redaction marker.
					if strings.HasPrefix(keyString, redactionMarkerPrefix) {
						redactionMarkers = append(redactionMarkers, keyString)
						delete(inputMap, rootKey)
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

	for _, redactionMarker := range redactionMarkers {
		keyToRedact := strings.TrimPrefix(redactionMarker, redactionMarkerPrefix)
		for rootKey := range inputMap {
			if keyString, ok := any(rootKey).(string); ok {
				if keyString == keyToRedact {
					inputMap[rootKey] = REDACTED
				}

				if keyString == redactionMarker {
					delete(inputMap, rootKey)
				}
			}
		}
	}

	return inputMap
}

func redactKey(k string) bool {
	// "routekey" shouldn't be redacted.
	// Add any other exceptions here.
	if k == "routekey" {
		return false
	}

	k = strings.ToLower(k)
	return strings.Contains(k, "auth") ||
		strings.Contains(k, "certificate") ||
		strings.Contains(k, "passphrase") ||
		strings.Contains(k, "password") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "key") ||
		strings.Contains(k, "secret")
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

		// Add the file to the zip.
		// Ignore files that don't exist to account for races with log rotation.
		if err := saveLogs(name, path, zw); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
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

// Redact redacts sensitive values from the passed mapStr.
func Redact(mapStr map[string]any, errOut io.Writer) map[string]any {
	return redactMap(errOut, mapStr, false)
}

// AddSecretMarkers adds secret redaction markers to the config by looking at the secret_paths field.
// It will add a marker to the config for each secret path.
// The marker is added to the config as a boolean field with the name of the
// secret path prefixed with "__mark_redact_".
func AddSecretMarkers(logger *logger.Logger, cfg *config.Config) error {
	secretPaths, err := getSecretPaths(logger, cfg)
	if err != nil {
		logger.Errorf("failed to get secret_paths: %v", err)
		return err
	}

	return addSecretMarkers(cfg, secretPaths)
}

func getSecretPaths(logger *logger.Logger, cfg *config.Config) ([]string, error) {
	if !cfg.Agent.HasField("secret_paths") {
		logger.Debugf("secret_paths field not found")
		return nil, nil
	}

	secretPaths, err := cfg.Agent.Child("secret_paths", -1)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret_paths: %w", err)
	}

	if !secretPaths.IsArray() {
		return nil, fmt.Errorf("secret_paths is not an array: %v", secretPaths)
	}

	res := []string{}
	if err := secretPaths.Unpack(&res); err != nil {
		return nil, fmt.Errorf("failed to unpack secret_paths: %w", err)
	}

	return res, nil
}

func addSecretMarkers(cfg *config.Config, secretPaths []string) error {
	var aggregateError error

	for _, sp := range secretPaths {
		ok, err := cfg.Agent.Has(sp, -1, ucfg.PathSep("."))
		if err != nil {
			aggregateError = errors.Join(aggregateError, fmt.Errorf("failed to check if %s exists: %w", sp, err))
			continue
		}

		if !ok {
			aggregateError = errors.Join(aggregateError, fmt.Errorf("secret path %s does not exist", sp))
			continue
		}

		lastPathSep := strings.LastIndex(sp, ".")
		parentPath := sp[:lastPathSep]
		keyName := sp[lastPathSep+1:]

		secretKeyName := redactionMarkerPrefix + keyName
		secretKeyPath := parentPath + "." + secretKeyName

		if err := cfg.Agent.SetBool(secretKeyPath, -1, true, ucfg.PathSep(".")); err != nil {
			aggregateError = errors.Join(aggregateError, fmt.Errorf("failed to set %s: %w", secretKeyPath, err))
			continue
		}
	}

	return aggregateError
}

func redactEnv() (map[string]any, error) {
	envMap := map[string]any{}
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		envMap[pair[0]] = pair[1]
	}
	var errOut bytes.Buffer
	redacted := Redact(envMap, &errOut)
	if errOut.Len() > 0 {
		return nil, errors.New(errOut.String())
	}
	return redacted, nil
}
