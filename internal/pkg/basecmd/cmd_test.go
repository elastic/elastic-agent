// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package basecmd

import (
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

func TestBaseCmd(t *testing.T) {
	streams, _, _, _ := cli.NewTestingIOStreams()
	NewDefaultCommandsWithArgs([]string{}, streams)
}
