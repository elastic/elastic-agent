//go:build darwin
// +build darwin

package tools

import (
	"fmt"
	"path/filepath"
)

func tarName(version string) (string, string, error) {
	arch, err := getArchFileTag()
	if err != nil {
		return "", "", err
	}
	fileName := fmt.Sprintf("elastic-agent-%s-darwin-%s.tar.gz", version, arch)
	destFileName := fmt.Sprintf("%s%s", "elastic-agent", filepath.Ext(fileName))
	return fileName, destFileName, nil
}
