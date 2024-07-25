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
