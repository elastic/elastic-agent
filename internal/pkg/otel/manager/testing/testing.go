// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"context"
	"errors"
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := cmd.RunCollector(ctx, nil, true)
	if err == nil || errors.Is(err, context.Canceled) {
		os.Exit(0)
	}
	os.Exit(1)
}
