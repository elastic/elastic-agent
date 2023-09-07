// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package env

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEnvWithDefault(t *testing.T) {
	def := "default"
	key1 := "ENV_WITH_DEFAULT_1"
	key2 := "ENV_WITH_DEFAULT_2"

	res := WithDefault(def, key1, key2)

	require.Equal(t, def, res)

	err := os.Setenv(key1, "key1")
	if err != nil {
		t.Skipf("could not export env var: %s", err)
	}

	err = os.Setenv(key2, "key2")
	if err != nil {
		t.Skipf("could not export env var: %s", err)
	}

	res2 := WithDefault(def, key1, key2)
	require.Equal(t, "key1", res2)
}

func TestEnvBool(t *testing.T) {
	key := "TEST_ENV_BOOL"

	err := os.Setenv(key, "true")
	if err != nil {
		t.Skipf("could not export env var: %s", err)
	}

	res := Bool(key)
	require.True(t, res)
}

func TestEnvTimeout(t *testing.T) {
	key := "TEST_ENV_TIMEOUT"

	err := os.Setenv(key, "10s")
	if err != nil {
		t.Skipf("could not export env var: %s", err)
	}

	res := Timeout(key)
	require.Equal(t, time.Second*10, res)
}
