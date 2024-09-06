// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package downloads

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMkdirAll(t *testing.T) {
	tmpDir := t.TempDir()

	dir := path.Join(tmpDir, ".op", "compose", "services")

	err := mkdirAll(dir)
	assert.Nil(t, err)

	e, _ := exists(dir)
	assert.True(t, e)
}
