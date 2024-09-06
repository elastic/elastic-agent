// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package downloads

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDownloadFile(t *testing.T) {
	var dRequest = downloadRequest{
		URL:          "https://www.elastic.co/robots.txt",
		DownloadPath: "",
	}
	err := downloadFile(&dRequest)
	assert.Nil(t, err)
	assert.NotEmpty(t, dRequest.UnsanitizedFilePath)
	defer os.Remove(filepath.Dir(dRequest.UnsanitizedFilePath))
}
