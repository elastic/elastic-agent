// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package ipc

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
)

func TestCreateListener(t *testing.T) {
	name := "npipe:///testpipe"

	// try creating and closing servers with same name multiple times
	for range 1000 {
		lis, err := CreateListener(logp.NewNopLogger(), name)
		require.NoError(t, err)
		require.NotNil(t, lis)
		s := &http.Server{}
		go func() {
			s.Serve(lis)
		}()
		require.NoError(t, s.Close())
	}
}
