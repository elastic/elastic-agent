// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/testing/estools"
)

func GetESHost() (string, error) {
	fixedESHost := os.Getenv("ELASTICSEARCH_HOST")
	parsedES, err := url.Parse(fixedESHost)
	if err != nil {
		return "", err
	}
	if parsedES.Port() == "" {
		fixedESHost = fmt.Sprintf("%s:443", fixedESHost)
	}
	return fixedESHost, nil
}

// FindESDocs runs `findFn` until at least one document is returned and there is no error
func FindESDocs(t *testing.T, findFn func() (estools.Documents, error)) estools.Documents {
	var docs estools.Documents
	require.Eventually(
		t,
		func() bool {
			var err error
			docs, err = findFn()
			if err != nil {
				t.Logf("got an error querying ES, retrying. Error: %s", err)
				return false
			}

			return docs.Hits.Total.Value != 0
		},
		3*time.Minute,
		15*time.Second,
	)

	return docs
}
