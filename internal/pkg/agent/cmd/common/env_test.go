// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEnvWithDefault(t *testing.T) {
	def := "default"
	key1 := "ENV_WITH_DEFAULT_1"
	key2 := "ENV_WITH_DEFAULT_2"

	res := EnvWithDefault(def, key1, key2)

	require.Equal(t, def, res)

	t.Setenv(key1, "key1")

	t.Setenv(key2, "key2")

	res2 := EnvWithDefault(def, key1, key2)
	require.Equal(t, "key1", res2)
}

func TestEnvBool(t *testing.T) {
	key := "TEST_ENV_BOOL"

	t.Setenv(key, "true")

	res := EnvBool(key)
	require.True(t, res)
}

func TestEnvTimeout(t *testing.T) {
	key := "TEST_ENV_TIMEOUT"

	t.Setenv(key, "10s")

	res := EnvTimeout(key)
	require.Equal(t, time.Second*10, res)
}
