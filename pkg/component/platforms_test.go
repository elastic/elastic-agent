// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadPlatformDetail(t *testing.T) {
	platformDetail, err := LoadPlatformDetail()
	assert.NoError(t, err)
	assert.NotEmpty(t, platformDetail)
}
