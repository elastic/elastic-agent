// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package quarkreceiver // import "github.com/elastic/elastic-agent/internal/edot/receivers/quarkreceiver"

import (
	"errors"
	"time"
)

// Config defines configuration for the quark receiver.
type Config struct {
	// Interval controls how often a log record is emitted. Defaults to 1s.
	Interval time.Duration `mapstructure:"interval"`

	// Message is the text set as the body of each emitted log record.
	// Defaults to "quark".
	Message string `mapstructure:"message"`
}

// Validate checks the receiver configuration for correctness.
func (c *Config) Validate() error {
	if c.Interval <= 0 {
		return errors.New("interval must be a positive duration")
	}
	return nil
}
