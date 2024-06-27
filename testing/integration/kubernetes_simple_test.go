// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package integration

import (
	"context"
	"testing"

	v1 "k8s.io/api/core/v1"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

func TestKubernetesSimple(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Kubernetes},
		},
		Group: define.Kubernetes,
	})

	ctx := context.Background()

	k8s, err := info.KubeClient()
	require.NoError(t, err)
	require.NotNil(t, k8s)

	podList := v1.PodList{}
	err = k8s.Resources().List(ctx, &podList)
	require.NoError(t, err)
	require.NotEmpty(t, podList.Items)
}
