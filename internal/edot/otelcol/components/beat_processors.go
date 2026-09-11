// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux || darwin || windows

package components

import (
	// Register beat processors used by the beatprocessor OTel component.
	// These processors use init() to register themselves with the beats processor
	// registry; they must be imported here because the edot binary does not import
	// the libbeat instance package that normally handles these registrations.
	_ "github.com/elastic/beats/v7/libbeat/processors/add_docker_metadata"
	_ "github.com/elastic/beats/v7/libbeat/processors/add_kubernetes_metadata"
)
