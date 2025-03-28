// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// GetOtelDependencies returns the Otel dependencies from the given go.mod. This function applies replace directives.
func GetOtelDependencies(goModPath string) (*OtelDependencies, error) {
	// read go.mod
	goModBytes, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}

	goModFileName := filepath.Base(goModPath)

	modFile, err := modfile.Parse(goModFileName, goModBytes, nil)
	if err != nil {
		return nil, err
	}

	var receivers, extensions, exporters, processors, connectors []*otelDependency
	// process imports
	pathToDep := make(map[string]*otelDependency)
	for _, req := range modFile.Require {
		dependency := newOtelDependency(req)
		if dependency == nil {
			continue
		}
		pathToDep[req.Mod.Path] = dependency

		if dependency.ComponentType == "connector" {
			connectors = append(connectors, dependency)
		} else if dependency.ComponentType == "exporter" {
			exporters = append(exporters, dependency)
		} else if dependency.ComponentType == "extension" {
			extensions = append(extensions, dependency)
		} else if dependency.ComponentType == "processor" {
			processors = append(processors, dependency)
		} else if dependency.ComponentType == "receiver" {
			receivers = append(receivers, dependency)
		}
	}

	for _, list := range [][]*otelDependency{connectors, exporters, extensions, processors, receivers} {
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	}

	// take care of replaces
	for _, rep := range modFile.Replace {
		otelDep, ok := pathToDep[rep.Old.Path]
		if ok {
			otelDep.applyReplace(rep)
		}
	}

	return &OtelDependencies{
		Connectors: connectors,
		Exporters:  exporters,
		Extensions: extensions,
		Processors: processors,
		Receivers:  receivers,
	}, nil
}

type otelDependency struct {
	ComponentType string
	Name          string
	Version       string
	Link          string
	req           *modfile.Require
}

func newOtelDependency(r *modfile.Require) *otelDependency {
	if !strings.Contains(r.Mod.Path, "go.opentelemetry.io/") &&
		!strings.Contains(r.Mod.Path, "github.com/open-telemetry/") &&
		!strings.Contains(r.Mod.Path, "github.com/elastic/opentelemetry-collector-components/") {
		return nil
	}

	if r.Indirect {
		return nil
	}

	componentName := getOtelComponentName(r.Mod.Path)
	componentType := getOtelComponentType(r.Mod.Path)
	link := getOtelDependencyLink(r.Mod.Path, r.Mod.Version)

	return &otelDependency{
		ComponentType: componentType,
		Name:          componentName,
		Version:       r.Mod.Version,
		Link:          link,
		req:           r,
	}
}

func (d *otelDependency) applyReplace(rep *modfile.Replace) {
	if rep == nil || rep.Old != d.req.Mod {
		return
	}
	d.Version = rep.New.Version
	d.req.Mod = rep.New
	d.Link = getOtelDependencyLink(rep.New.Path, rep.New.Version)
}

func getOtelComponentName(dependencyName string) string {
	parts := strings.Split(dependencyName, "/")
	return parts[len(parts)-1]
}

func getOtelComponentType(dependencyName string) string {
	if strings.Contains(dependencyName, "/connector/") {
		return "connector"
	} else if strings.Contains(dependencyName, "/exporter/") {
		return "exporter"
	} else if strings.Contains(dependencyName, "/extension/") {
		return "extension"
	} else if strings.Contains(dependencyName, "/processor/") {
		return "processor"
	} else if strings.Contains(dependencyName, "/receiver/") {
		return "receiver"
	}
	return ""
}

func getOtelDependencyLink(dependencyURI string, version string) string {
	dependencyRepository := getDependencyRepository(dependencyURI)
	dependencyPath := strings.TrimPrefix(dependencyURI, dependencyRepository+"/")
	gitRevision := fmt.Sprintf("%s/%s", dependencyPath, version)
	repositoryURL := getOtelRepositoryURL(dependencyURI)
	// if the version is a pseudo-version pointing to a revision without a tag, we need to extract the revision
	if module.IsPseudoVersion(version) {
		revision, err := module.PseudoVersionRev(version)
		if err == nil { // this should never return an error, as we check it earlier
			gitRevision = revision
		}
	}
	return fmt.Sprintf("https://%s/blob/%s/%s/README.md", repositoryURL, gitRevision, dependencyPath)
}

func getDependencyRepository(dependencyURI string) string {
	dependencyURIChunks := strings.Split(dependencyURI, "/")
	if len(dependencyURIChunks) < 2 {
		return ""
	}
	var dependencyRepository string
	if dependencyURIChunks[0] == "go.opentelemetry.io" {
		dependencyRepository = dependencyURIChunks[0] + "/" + dependencyURIChunks[1]
	} else {
		dependencyRepository = dependencyURIChunks[0] + "/" + dependencyURIChunks[1] + "/" + dependencyURIChunks[2]
	}
	return dependencyRepository
}

func getOtelRepositoryURL(dependencyURI string) string {
	if strings.HasPrefix(dependencyURI, "go.opentelemetry.io/") {
		return "github.com/open-telemetry/opentelemetry-collector"
	} else if strings.HasPrefix(dependencyURI, "github.com/") {
		parts := strings.SplitN(dependencyURI, "/", 4)
		hostPart := parts[0]
		orgPart := parts[1]
		repoPart := parts[2]
		return fmt.Sprintf("%s/%s/%s", hostPart, orgPart, repoPart)
	}
	return ""
}

type OtelDependencies struct {
	Connectors []*otelDependency
	Exporters  []*otelDependency
	Extensions []*otelDependency
	Processors []*otelDependency
	Receivers  []*otelDependency
}
