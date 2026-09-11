// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build securityonly

package beats

import "github.com/spf13/cobra"

// AddCommands is intentionally a no-op for the endpoint variant build: beat
// subcommands are the only mechanism by which the collector can exec a beat
// in process mode, so omitting them makes process mode impossible at the
// binary level.
func AddCommands(_ *cobra.Command) {}
