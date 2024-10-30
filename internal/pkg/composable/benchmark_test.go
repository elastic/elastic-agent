// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package composable

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/uuid"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/stretchr/testify/require"
)

// BenchmarkGenerateVars100Pods checks the cost of generating vars with the kubernetes provider tracking 100 Pods.
// This scenario does come up in reality, in particular in our internal Serverless clusters, and we've historically
// had bad performance in it. Test data is taken almost directly from a real cluster.
func BenchmarkGenerateVars100Pods(b *testing.B) {
	log, err := logger.New("", false)
	require.NoError(b, err)
	c := controller{
		contextProviders: make(map[string]*contextProviderState),
		dynamicProviders: make(map[string]*dynamicProviderState),
		logger:           log,
	}
	podCount := 100

	providerDataFiles, err := os.ReadDir("./testdata")
	require.NoError(b, err)

	providerData := make(map[string]map[string]interface{}, len(providerDataFiles))
	for _, providerDataFile := range providerDataFiles {
		fileName := providerDataFile.Name()
		providerName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
		rawData, err := os.ReadFile(filepath.Join("./testdata", fileName))
		require.NoError(b, err)
		var data map[string]interface{}
		err = yaml.Unmarshal(rawData, &data)
		require.NoError(b, err)
		providerData[providerName] = data
	}

	for providerName, providerMapping := range providerData {
		if providerName == "kubernetes" {
			providerState := &dynamicProviderState{
				mappings: make(map[string]dynamicProviderMapping),
			}
			for i := 0; i < podCount; i++ {
				podData, err := transpiler.NewAST(providerMapping)
				require.NoError(b, err)
				podUID := uuid.NewUUID()
				podMapping := dynamicProviderMapping{
					mapping: podData,
				}
				providerState.mappings[string(podUID)] = podMapping
			}
			c.dynamicProviders[providerName] = providerState
		} else {
			providerState := &contextProviderState{
				mapping: providerData[providerName],
			}
			c.contextProviders[providerName] = providerState
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.generateVars(mapstr.M{})
	}
}
