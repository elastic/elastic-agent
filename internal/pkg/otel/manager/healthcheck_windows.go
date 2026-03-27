// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package manager

import (
	"fmt"
	"net/url"

	"github.com/elastic/elastic-agent-libs/api/npipe"
)

func parseEndpoint(endpoint string) (scheme, path string, err error) {
	endpointUrl, err := url.Parse(endpoint)
	if err != nil {
		return "", "", fmt.Errorf("error parsing url %s: %w", endpoint, err)
	}
	if endpointUrl.Scheme == "npipe" {
		path = npipe.TransformString(endpoint)
	} else {
		path = endpointUrl.Path
	}
	return endpointUrl.Scheme, path, nil
}
