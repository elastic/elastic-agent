// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

// RenderKustomize renders the given kustomize directory to YAML
func RenderKustomize(ctx context.Context, kustomizePath string) ([]byte, error) {
	kustomizeYaml, err := backoff.Retry(ctx, func() ([]byte, error) {
		// Create a file system pointing to the kustomize directory
		fSys := filesys.MakeFsOnDisk()
		// Create a kustomizer
		k := krusty.MakeKustomizer(krusty.MakeDefaultOptions())
		// Run the kustomizer on the given directory
		resMap, err := k.Run(fSys, kustomizePath)
		if err != nil {
			return nil, fmt.Errorf("error running kustomizer: %w", err)
		}

		// Convert the result to YAML
		renderedManifest, err := resMap.AsYaml()
		if err != nil {
			return nil, fmt.Errorf("error rendering kustomize: %w", err)
		}

		return renderedManifest, nil
	},
		backoff.WithBackOff(backoff.NewConstantBackOff(1*time.Second)),
		backoff.WithMaxTries(10),
	)

	if err != nil {
		return nil, fmt.Errorf("error rendering kustomize: %w", err)
	}

	return kustomizeYaml, nil
}
