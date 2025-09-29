// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring"
	componentmonitoring "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"
	"github.com/elastic/elastic-agent/internal/pkg/otel"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
)

var fileBeatRegistryPathRegExps = getRegexpsForRegistryFiles()

// PerformDiagnostics executes the diagnostic action for the provided units. If no units are provided then
// it performs diagnostics for all current units. If a given unit does not exist in the manager, then a warning
// is logged.
func (m *OTelManager) PerformDiagnostics(ctx context.Context, req ...runtime.ComponentUnitDiagnosticRequest) []runtime.ComponentUnitDiagnostic {
	var diagnostics []runtime.ComponentUnitDiagnostic
	m.mx.RLock()
	currentComponents := m.components
	m.mx.RUnlock()

	// if no request is provided, then perform diagnostics for all units
	if len(req) == 0 {
		for _, comp := range currentComponents {
			for _, unit := range comp.Units {
				diagnostics = append(diagnostics, runtime.ComponentUnitDiagnostic{
					Component: comp,
					Unit:      unit,
				})
			}
		}
		return diagnostics
	}

	// create a map of unit by component and unit id, this is used to filter out units that
	// do not exist in the manager
	unitByID := make(map[string]map[string]*component.Unit)
	for _, r := range req {
		if unitByID[r.Component.ID] == nil {
			unitByID[r.Component.ID] = make(map[string]*component.Unit)
		}
		unitByID[r.Component.ID][r.Unit.ID] = &r.Unit
	}

	// create empty diagnostics for units that exist in the manager
	for _, existingComp := range currentComponents {
		inputComp, ok := unitByID[existingComp.ID]
		if !ok {
			m.logger.Warnf("requested diagnostics for component %s, but it does not exist in the manager", existingComp.ID)
			continue
		}
		for _, unit := range existingComp.Units {
			if _, ok := inputComp[unit.ID]; ok {
				diagnostics = append(diagnostics, runtime.ComponentUnitDiagnostic{
					Component: existingComp,
					Unit:      unit,
				})
			} else {
				m.logger.Warnf("requested diagnostics for unit %s, but it does not exist in the manager", unit.ID)
			}
		}
	}

	return diagnostics
}

// PerformComponentDiagnostics executes the diagnostic action for the provided components. If no components are provided,
// then it performs the diagnostics for all current components.
func (m *OTelManager) PerformComponentDiagnostics(
	ctx context.Context, additionalMetrics []cproto.AdditionalDiagnosticRequest, req ...component.Component,
) ([]runtime.ComponentDiagnostic, error) {
	var diagnostics []runtime.ComponentDiagnostic
	m.mx.RLock()
	currentComponents := m.components
	m.mx.RUnlock()

	// if no request is provided, then perform diagnostics for all components
	if len(req) == 0 {
		req = currentComponents
	}

	// create a map of component by id, this is used to filter out components that do not exist in the manager
	compByID := make(map[string]component.Component)
	for _, comp := range req {
		compByID[comp.ID] = comp
	}

	// create empty diagnostics for components that exist in the manager
	for _, existingComp := range currentComponents {
		if inputComp, ok := compByID[existingComp.ID]; ok {
			diagnostics = append(diagnostics, runtime.ComponentDiagnostic{
				Component: inputComp,
			})
		} else {
			m.logger.Warnf("requested diagnostics for component %s, but it does not exist in the manager", existingComp.ID)
		}
	}

	extDiagnostics, err := otel.PerformDiagnosticsExt(ctx, false)
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		// We're not running the EDOT if:
		//  1. Either the socket doesn't exist
		//	2. It is refusing the connections.
		m.logger.Debugf("Couldn't fetch diagnostics from EDOT: %v", err)
		return diagnostics, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error fetching otel diagnostics: %w", err)
	}

	for idx, diag := range diagnostics {
		for _, extDiag := range extDiagnostics.ComponentDiagnostics {
			if strings.Contains(extDiag.Name, diag.Component.ID) {
				diagnostics[idx].Results = append(diag.Results, extDiag)
			}
		}
	}

	for idx, diag := range diagnostics {
		var results []*proto.ActionDiagnosticUnitResult
		var errs []error
		jsonMetricDiagnostic, err := GetBeatJsonMetricsDiagnostics(ctx, diag.Component.ID)
		errs = append(errs, err)
		if jsonMetricDiagnostic != nil {
			results = append(results, jsonMetricDiagnostic)
		}

		inputMetricsDiagnostic, err := GetBeatInputMetricsDiagnostics(ctx, diag.Component.ID)
		errs = append(errs, err)
		if inputMetricsDiagnostic != nil {
			results = append(results, inputMetricsDiagnostic)
		}

		if translate.GetBeatNameForComponent(&diag.Component) == "filebeat" {
			// include filebeat registry, reimplementation of a filebeat diagnostic hook
			registryTarGzBytes, err := FileBeatRegistryTarGz(m.logger, diag.Component.ID)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to get filebeat registry archive: %w", err))
			}
			if registryTarGzBytes != nil {
				m.logger.Debugf("created registry tar.gz, size %d", len(registryTarGzBytes))
				results = append(results, &proto.ActionDiagnosticUnitResult{
					Name:        "registry",
					Description: "Filebeat's registry",
					Filename:    "registry.tar.gz",
					ContentType: "application/octet-stream",
					Content:     registryTarGzBytes,
					Generated:   timestamppb.Now(),
				})
			}

		}

		diagnostics[idx].Results = append(diagnostics[idx].Results, results...)
		diagnostics[idx].Err = errors.Join(errs...)
	}

	return diagnostics, nil
}

func GetBeatJsonMetricsDiagnostics(ctx context.Context, componentID string) (*proto.ActionDiagnosticUnitResult, error) {
	beatMetrics, err := GetBeatMetricsPayload(ctx, componentID, "/stats")
	if err != nil {
		return nil, fmt.Errorf("failed to get stats beat metrics: %w", err)
	}

	beatMetrics, err = formatJSON(beatMetrics)
	if err != nil {
		return nil, fmt.Errorf("failed to format stats beat metrics: %w", err)
	}

	result := &proto.ActionDiagnosticUnitResult{
		Name:        "beat_metrics",
		Description: "Metrics from the default monitoring namespace and expvar.",
		Filename:    "beat_metrics.json",
		ContentType: "application/json",
		Content:     beatMetrics,
		Generated:   timestamppb.Now(),
	}
	return result, nil
}

func GetBeatInputMetricsDiagnostics(ctx context.Context, componentID string) (*proto.ActionDiagnosticUnitResult, error) {
	inputMetrics, err := GetBeatMetricsPayload(ctx, componentID, "/inputs/")
	if err != nil {
		return nil, fmt.Errorf("failed to get input beat metrics: %w", err)
	}

	inputMetrics, err = formatJSON(inputMetrics)
	if err != nil {
		return nil, fmt.Errorf("failed to format input beat metrics: %w", err)
	}

	result := &proto.ActionDiagnosticUnitResult{
		Name:        "input_metrics",
		Description: "Metrics from active inputs.",
		Filename:    "input_metrics.json",
		ContentType: "application/json",
		Content:     inputMetrics,
		Generated:   timestamppb.Now(),
	}
	return result, nil
}

func GetBeatMetricsPayload(ctx context.Context, componentID string, path string) ([]byte, error) {
	endpoint := componentmonitoring.PrefixedEndpoint(componentmonitoring.BeatsMonitoringEndpoint(componentID))
	metricBytes, statusCode, err := monitoring.GetProcessMetrics(ctx, endpoint, path)
	if err != nil {
		return nil, err
	}
	if statusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code %d", statusCode)
	}
	return metricBytes, nil
}

func formatJSON(jsonBytes []byte) ([]byte, error) {
	// remarshal the metrics to produce nicely formatted json
	var data any
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return nil, err
	}

	formattedData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, err
	}
	return formattedData, nil
}

func FileBeatRegistryPath(componentID string) string {
	dataPath := translate.BeatDataPath(componentID)
	return filepath.Join(dataPath, "registry")
}

// FileBeatRegistryTarGz creates a tar.gz file containing the filebeat registry and returns its contents as bytes.
func FileBeatRegistryTarGz(logger *logger.Logger, componentID string) ([]byte, error) {
	registryPath := FileBeatRegistryPath(componentID)

	tempFile, err := os.CreateTemp("", "temp-registry.tar.gz")
	if err != nil {
		return nil, err
	}

	defer func() {
		if closeErr := tempFile.Close(); closeErr != nil {
			logger.Warn("error closing temporary registry archive", "error", closeErr)
		}
		if removeErr := os.Remove(tempFile.Name()); removeErr != nil {
			logger.Warnf("cannot remove temporary registry archive '%s': '%s'", tempFile.Name(), removeErr)
		}
	}()

	gzWriter := gzip.NewWriter(tempFile)
	defer func() {
		if closeErr := gzWriter.Close(); closeErr != nil {
			logger.Warnf("error closing gzip writer: %v", closeErr)
		}
	}()

	err = tarFolder(logger, gzWriter, registryPath)
	if err != nil {
		return nil, err
	}
	if closeErr := gzWriter.Close(); closeErr != nil {
		return nil, closeErr
	}

	stat, err := tempFile.Stat()
	if err != nil {
		return nil, err
	}

	if stat.Size() > 20_000_000 {
		return nil, fmt.Errorf("registry is too large for diagnostics, %d > 20mb", stat.Size()/1_000_000)
	}

	var output bytes.Buffer
	_, err = tempFile.Seek(0, 0)
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(&output, tempFile)
	if err != nil {
		return nil, err
	}

	return output.Bytes(), nil
}

// getRegexpsForRegistryFiles returns a list of regexps to match filebeat registry files.
func getRegexpsForRegistryFiles() []*regexp.Regexp {
	var registryFileRegExps []*regexp.Regexp
	preFilesList := [][]string{
		{"^registry$"},
		{"^registry", "filebeat$"},
		{"^registry", "filebeat", "meta\\.json$"},
		{"^registry", "filebeat", "log\\.json$"},
		{"^registry", "filebeat", "active\\.dat$"},
		{"^registry", "filebeat", "[[:digit:]]*\\.json$"},
	}

	for _, lst := range preFilesList {
		// On windows, we need to ensure we escape the path separator, because backslash has a special meaning
		separator := regexp.QuoteMeta(string(filepath.Separator))
		pathRe := strings.Join(lst, separator)
		re := regexp.MustCompile(pathRe)
		registryFileRegExps = append(registryFileRegExps, re)
	}

	return registryFileRegExps
}

// tarFolder creates a tar archive from the folder src and stores it at dst.
//
// dst must be the full path with extension, e.g: /tmp/foo.tar
// If src is not a folder an error is returned
func tarFolder(logger *logger.Logger, dst io.Writer, srcPath string) error {
	fullPath, err := filepath.Abs(srcPath)
	if err != nil {
		return fmt.Errorf("cannot get full path from '%s': '%w'", srcPath, err)
	}

	tarWriter := tar.NewWriter(dst)
	defer func() {
		if err := tarWriter.Close(); err != nil {
			logger.Warnf("cannot close tar writer: '%s'", err)
		}
	}()

	info, err := os.Stat(fullPath)
	if err != nil {
		return fmt.Errorf("cannot stat '%s': '%w'", fullPath, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("'%s' is not a directory", fullPath)
	}
	baseDir := filepath.Base(srcPath)

	logger.Debugf("starting to walk '%s'", fullPath)

	return filepath.Walk(fullPath, func(path string, info fs.FileInfo, prevErr error) error {
		// Stop if there is any errors
		if prevErr != nil {
			return prevErr
		}

		pathInTar := filepath.Join(baseDir, strings.TrimPrefix(path, srcPath))
		if !matchRegistryFiles(fileBeatRegistryPathRegExps, pathInTar) {
			return nil
		}
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return fmt.Errorf("cannot create tar info header: '%w'", err)
		}
		header.Name = pathInTar

		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("cannot write tar header for '%s': '%w'", path, err)
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("cannot open '%s' for reading: '%w", path, err)
		}
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				logger.Warnf("cannot close file '%s': '%s'", path, closeErr)
			}
		}()

		logger.Debugf("adding '%s' to the tar archive", file.Name())
		if _, err := io.Copy(tarWriter, file); err != nil {
			return fmt.Errorf("cannot read '%s': '%w'", path, err)
		}

		return nil
	})
}

func matchRegistryFiles(registryFileRegExps []*regexp.Regexp, path string) bool {
	for _, regExp := range registryFileRegExps {
		if regExp.MatchString(path) {
			return true
		}
	}
	return false
}
