// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package downloads

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDownloadFile(t *testing.T) {
	s := httptest.NewServer(http.FileServer(http.Dir("./testdata")))
	t.Cleanup(s.Close)

	var dRequest = downloadRequest{
		URL: fmt.Sprintf("http://%s/some-file.txt",
			s.Listener.Addr().String()),
		DownloadPath: "",
	}

	err := downloadFile(&dRequest)
	assert.Nil(t, err)
	assert.NotEmpty(t, dRequest.UnsanitizedFilePath)
	defer os.Remove(filepath.Dir(dRequest.UnsanitizedFilePath))
}
