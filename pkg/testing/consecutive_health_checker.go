// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"context"
	"fmt"
)

// ConsecutiveHealthChecker wraps IsHealthy for use in long-running polling loops.
// It returns nil until the agent has been unhealthy for maxConsecutive checks in a row,
// then returns the error. The counter resets on any healthy response.
//
// Use this instead of bare IsHealthy + require.NoError in custom polling loops.
// For one-shot health checks after an operation, use IsHealthy inside require.Eventually instead.
type ConsecutiveHealthChecker struct {
	fixture     *Fixture
	max         int
	consecutive int
}

// NewConsecutiveHealthChecker returns a checker that tolerates up to maxConsecutive
// consecutive unhealthy responses before reporting an error.
func NewConsecutiveHealthChecker(fixture *Fixture, maxConsecutive int) *ConsecutiveHealthChecker {
	return &ConsecutiveHealthChecker{fixture: fixture, max: maxConsecutive}
}

// Check calls IsHealthy and returns nil as long as the agent has not been
// unhealthy for maxConsecutive consecutive calls. It resets the counter on
// any healthy response.
func (c *ConsecutiveHealthChecker) Check(ctx context.Context) error {
	err := c.fixture.IsHealthy(ctx)
	if err != nil {
		c.consecutive++
		if c.consecutive >= c.max {
			return fmt.Errorf("unhealthy for %d consecutive checks: %w", c.consecutive, err)
		}
		return nil
	}
	c.consecutive = 0
	return nil
}
