// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dispatcher

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_retryConfig_GetWait(t *testing.T) {
	rt := defaultRetryConfig()

	t.Run("step is negative", func(t *testing.T) {
		d, err := rt.GetWait(-1)
		assert.Equal(t, time.Duration(0), d)
		assert.ErrorIs(t, err, ErrNoRetry)
	})

	t.Run("returns duration", func(t *testing.T) {
		d, err := rt.GetWait(0)
		assert.Equal(t, time.Minute, d)
		assert.NoError(t, err)
	})

	t.Run("step too large", func(t *testing.T) {
		d, err := rt.GetWait(len(rt.steps))
		assert.Equal(t, time.Duration(0), d)
		assert.ErrorIs(t, err, ErrNoRetry)
	})
}
