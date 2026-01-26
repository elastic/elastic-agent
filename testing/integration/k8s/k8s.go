// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package k8s

import "path/filepath"

const (
	KubeStackChartVersion         = "0.13.1"
	KubeStackChartName            = "opentelemetry-kube-stack"
	KubeStackChartNameWithVersion = KubeStackChartName + "-" + KubeStackChartVersion
	KubeStackChartArchiveName     = KubeStackChartNameWithVersion + ".tgz"
	KubeStackChartURL             = "https://github.com/open-telemetry/opentelemetry-helm-charts/releases/download/" + KubeStackChartNameWithVersion + "/" + KubeStackChartArchiveName
)

var (
	AgentKustomizePath = filepath.Join("testdata", "elastic-agent-kustomize.yaml")
	AgentHelmChartPath = filepath.Join("..", "..", "..", "deploy", "helm", "elastic-agent")

	KubeStackChartPath = filepath.Join("testdata", KubeStackChartName)
)
