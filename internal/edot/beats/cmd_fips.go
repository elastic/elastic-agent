// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package beats

import (
	"github.com/spf13/cobra"

	auditbeat "github.com/elastic/beats/v7/x-pack/auditbeat/cmd"
	filebeat "github.com/elastic/beats/v7/x-pack/filebeat/cmd"
	metricbeat "github.com/elastic/beats/v7/x-pack/metricbeat/cmd"
)

func AddCommands(cmd *cobra.Command) {
	cmd.AddCommand(
		prepareCommand(auditbeat.RootCmd),
		prepareCommand(filebeat.Filebeat()),
		prepareCommand(metricbeat.Initialize()),
	)
}
