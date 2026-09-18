// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetapi

import api "github.com/elastic/fleet-server/pkg/api"

// AckRequest is re-exported from fleet-server's pkg/api for callers that don't want
// to import fleet-server directly.
type AckRequest = api.AckRequest

// AckResponseItem is re-exported from fleet-server's pkg/api for callers that don't want
// to import fleet-server directly.
type AckResponseItem = api.AckResponseItem

// AckResponse is re-exported from fleet-server's pkg/api for callers that don't want
// to import fleet-server directly.
type AckResponse = api.AckResponse
