// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !linux

package cmd

import (
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

func initContainer(_ *cli.IOStreams) {}
