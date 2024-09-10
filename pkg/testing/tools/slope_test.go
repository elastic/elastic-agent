// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package tools

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSlopeMeasurement(t *testing.T) {

	testCases := []struct {
		name       string
		datapoints []float64
		test       func(slope float64, t *testing.T)
	}{
		{
			name: "good handle counts",
			datapoints: []float64{17.00, 13.00, 16.00, 13.00, 17.00, 13.00, 16.00, 13.00, 16.00, 14.00,
				18.00, 15.00, 12.00, 16.00, 14.00, 18.00, 14.00, 17.00, 15.00, 18.00, 15.00, 18.00, 15.00, 18.00,
				14.00, 18.00, 14.00, 17.00, 13.00,
			},
			test: func(slope float64, t *testing.T) {
				require.LessOrEqual(t, slope, 0.01)
			},
		},
		{
			name: "bad handle counts",
			datapoints: []float64{967, 1097, 2190, 3099, 3906, 4390, 5239, 6209, 7097, 7989, 8890, 9976,
				10957, 11679, 12907, 13806, 13969, 14898, 16103, 17207, 18109, 19459, 21004, 21947},
			test: func(slope float64, t *testing.T) {
				require.Greater(t, slope, 1.00)
			},
		},
	}

	for _, test := range testCases {
		testHandle := NewSlope("test")
		startingTime := 10
		for _, handleCount := range test.datapoints {
			testHandle.AddDatapoint(handleCount, time.Second*time.Duration(startingTime))
			startingTime += 10
		}
		err := testHandle.Run()
		require.NoError(t, err)
		test.test(testHandle.GetSlope(), t)
	}
}
