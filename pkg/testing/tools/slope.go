// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package tools

import (
	"time"

	"github.com/sajari/regression"
)

// Slope is a slim wrapper around a regression library for calculating rate of change over time in tests.
type Slope struct {
	handler *regression.Regression
	label   string
}

func NewSlope(label string) Slope {
	handler := new(regression.Regression)
	handler.SetObserved(label)
	handler.SetVar(0, "time")
	return Slope{handler: handler, label: label}
}

// add a datapoint and timestamp to the calculaton.
func (slope Slope) AddDatapoint(count float64, timeSinceStart time.Duration) {
	slope.handler.Train(regression.DataPoint(count, []float64{timeSinceStart.Seconds()}))
}

// Run the regression on the supplied data
func (slope Slope) Run() error {
	return slope.handler.Run()
}

// return the slope of the regression
func (slope Slope) GetSlope() float64 {
	return slope.handler.GetCoeffs()[1]
}

// Formula returns a string representation of the regression formula
func (slope Slope) Formula() string {
	return slope.handler.Formula
}

// Debug returns a string representation of the regression, including all datapoints
func (slope Slope) Debug() string {
	return slope.handler.String()
}

func (slope Slope) Name() string {
	return slope.label
}
