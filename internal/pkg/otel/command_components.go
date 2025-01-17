// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"fmt"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"sort"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/receiver"

	"github.com/elastic/elastic-agent/internal/pkg/release"
)

type componentWithStability struct {
	Name      component.Type
	Module    string
	Stability map[string]string
}

type componentsOutput struct {
	BuildInfo  component.BuildInfo
	Receivers  []componentWithStability
	Processors []componentWithStability
	Exporters  []componentWithStability
	Connectors []componentWithStability
	Extensions []componentWithStability
}

func Components(cmd *cobra.Command) error {
	set := NewSettings(release.Version(), []string{})

	factories, err := set.Factories()
	if err != nil {
		return fmt.Errorf("failed to initialize factories: %w", err)
	}

	components := componentsOutput{}
	for _, con := range sortFactoriesByType[connector.Factory](factories.Connectors) {
		components.Connectors = append(components.Connectors, componentWithStability{
			Name:   con.Type(),
			Module: factories.ConnectorModules[con.Type()],
			Stability: map[string]string{
				"logs-to-logs":    con.LogsToLogsStability().String(),
				"logs-to-metrics": con.LogsToMetricsStability().String(),
				"logs-to-traces":  con.LogsToTracesStability().String(),

				"metrics-to-logs":    con.MetricsToLogsStability().String(),
				"metrics-to-metrics": con.MetricsToMetricsStability().String(),
				"metrics-to-traces":  con.MetricsToTracesStability().String(),

				"traces-to-logs":    con.TracesToLogsStability().String(),
				"traces-to-metrics": con.TracesToMetricsStability().String(),
				"traces-to-traces":  con.TracesToTracesStability().String(),
			},
		})
	}
	for _, ext := range sortFactoriesByType[extension.Factory](factories.Extensions) {
		components.Extensions = append(components.Extensions, componentWithStability{
			Name:   ext.Type(),
			Module: factories.ExtensionModules[ext.Type()],
			Stability: map[string]string{
				"extension": ext.Stability().String(),
			},
		})
	}
	for _, prs := range sortFactoriesByType[processor.Factory](factories.Processors) {
		components.Processors = append(components.Processors, componentWithStability{
			Name:   prs.Type(),
			Module: factories.ProcessorModules[prs.Type()],
			Stability: map[string]string{
				"logs":    prs.LogsStability().String(),
				"metrics": prs.MetricsStability().String(),
				"traces":  prs.TracesStability().String(),
			},
		})
	}
	for _, rcv := range sortFactoriesByType[receiver.Factory](factories.Receivers) {
		components.Receivers = append(components.Receivers, componentWithStability{
			Name:   rcv.Type(),
			Module: factories.ReceiverModules[rcv.Type()],
			Stability: map[string]string{
				"logs":    rcv.LogsStability().String(),
				"metrics": rcv.MetricsStability().String(),
				"traces":  rcv.TracesStability().String(),
			},
		})
	}
	for _, exp := range sortFactoriesByType[exporter.Factory](factories.Exporters) {
		components.Exporters = append(components.Exporters, componentWithStability{
			Name:   exp.Type(),
			Module: factories.ExporterModules[exp.Type()],
			Stability: map[string]string{
				"logs":    exp.LogsStability().String(),
				"metrics": exp.MetricsStability().String(),
				"traces":  exp.TracesStability().String(),
			},
		})
	}
	components.BuildInfo = set.BuildInfo

	yamlData, err := yaml.Marshal(components)
	if err != nil {
		return err
	}
	fmt.Fprint(cmd.OutOrStdout(), string(yamlData))
	return nil
}

func sortFactoriesByType[T component.Factory](factories map[component.Type]T) []T {
	// Gather component types (factories map keys)
	componentTypes := make([]component.Type, 0, len(factories))
	for componentType := range factories {
		componentTypes = append(componentTypes, componentType)
	}

	// Sort component types as strings
	sort.Slice(componentTypes, func(i, j int) bool {
		return componentTypes[i].String() < componentTypes[j].String()
	})

	// Build and return list of factories, sorted by component types
	sortedFactories := make([]T, 0, len(factories))
	for _, componentType := range componentTypes {
		sortedFactories = append(sortedFactories, factories[componentType])
	}

	return sortedFactories
}
