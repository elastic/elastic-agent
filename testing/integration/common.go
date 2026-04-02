// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/testing/estools"
)

func GetESHost() (string, error) {
	fixedESHost := os.Getenv("ELASTICSEARCH_HOST")
	if len(fixedESHost) == 0 {
		return "", errors.New("ELASTICSEARCH_HOST cannot be empty")
	}
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
	require.EventuallyWithT(
		t,
		func(c *assert.CollectT) {
			var err error
			docs, err = findFn()
			require.NoErrorf(c, err, "got an error querying ES, retrying. Error: %s", err)
			require.NotEqualValues(c, 0, docs.Hits.Total.Value, "expecting at least one document returned by 'findFn'")
		},
		3*time.Minute,
		15*time.Second,
		"did not find the expected documents on ES")

	return docs
}
