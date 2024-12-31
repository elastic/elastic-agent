// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

type testKibanaApiKey struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Active   bool   `json:"active"`
	PolicyID string `json:"policy_id"`
	APIKey   string `json:"api_key"`
}

type deprecatedBody struct {
	List []testKibanaApiKey `json:"list"`
}

type newBody struct {
	Items []testKibanaApiKey `json:"items"`
}

// TODO: Remove test after list deprecation is complete
// Added by https://github.com/elastic/elastic-agent/pull/6437
func TestItemsMatchDeprecatedList(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{},
		Local: true,
		Sudo:  false,
	})

	res, err := info.KibanaClient.Connection.Send(http.MethodGet, "/api/fleet/enrollment_api_keys", nil, nil, nil)
	require.NoError(t, err)
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	dpb := deprecatedBody{}
	nb := newBody{}

	err = json.Unmarshal(body, &dpb)
	require.NoError(t, err)

	err = json.Unmarshal(body, &nb)
	require.NoError(t, err)

	require.Equal(t, len(dpb.List), len(nb.Items))
	for i := 0; i < len(dpb.List); i++ {
		require.Equal(t, dpb.List[i], nb.Items[i])
	}
}
