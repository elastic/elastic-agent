// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !integration

package kubestack

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"helm.sh/helm/v4/pkg/chart/common"
	chartutil "helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/chart/loader"
	"helm.sh/helm/v4/pkg/engine"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func TestDotNetInstrumentation(t *testing.T) {
	for _, valuesFile := range []string{"values.yaml", filepath.Join("managed_otlp", "values.yaml")} {
		t.Run(valuesFile, func(t *testing.T) {
			chartPath := filepath.Join("..", "..", "..", "..", "testing", "integration", "k8s", "testdata", "opentelemetry-kube-stack")
			helmChart, err := loader.Load(chartPath)
			require.NoError(t, err)

			helmValues, err := common.ReadValuesFile(valuesFile)
			require.NoError(t, err)
			renderValues, err := chartutil.ToRenderValues(helmChart, helmValues, common.ReleaseOptions{
				Name:      "dotnet-instrumentation-test",
				Namespace: "opentelemetry-operator-system",
				IsInstall: true,
			}, nil)
			require.NoError(t, err)

			rendered, err := new(engine.Engine).RenderWithContext(t.Context(), helmChart, renderValues)
			require.NoError(t, err)
			const manifestKey = "opentelemetry-kube-stack/templates/instrumentation.yaml"
			require.Contains(t, rendered, manifestKey)

			var instrumentation struct {
				Kind string `json:"kind"`
				Spec struct {
					DotNet struct {
						Image string          `json:"image"`
						Env   []corev1.EnvVar `json:"env"`
					} `json:"dotnet"`
				} `json:"spec"`
			}
			require.NoError(t, yaml.Unmarshal([]byte(rendered[manifestKey]), &instrumentation))
			require.Equal(t, "Instrumentation", instrumentation.Kind)
			require.Contains(t, instrumentation.Spec.DotNet.Image, "docker.elastic.co/observability/elastic-otel-dotnet:")
			require.Contains(t, instrumentation.Spec.DotNet.Env, corev1.EnvVar{
				Name:  "OTEL_DOTNET_AUTO_PLUGINS",
				Value: "Elastic.OpenTelemetry.AutoInstrumentationPlugin, Elastic.OpenTelemetry.AutoInstrumentation",
			})
		})
	}
}
