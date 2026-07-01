// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:generate mdatagen metadata.yaml

// Package quarkreceiver is a development-stage mock OTel receiver that emits one
// log entry per configured interval. It serves as a scaffold and test harness
// while real receiver logic is developed.
//
// # Configuration
//
//	receivers:
//	  quark:
//	    interval: 1s      # How often to emit a log record (default: 1s)
//	    message: "quark"  # Body text of each emitted log record (default: "quark")
//
// # Output
//
// Each tick produces one plog.Logs with a single log record. The record has
// SeverityNumber INFO and its body set to the configured message text.
package quarkreceiver // import "github.com/elastic/elastic-agent/internal/edot/receivers/quarkreceiver"
