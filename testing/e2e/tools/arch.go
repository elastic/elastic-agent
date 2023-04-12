//go:build linux || darwin
// +build linux darwin

package tools

import (
	"fmt"
	"runtime"
)

func getArchFileTag() (string, error) {
	if runtime.GOARCH == "amd64" {
		return "x86_64", nil
	} else if runtime.GOARCH == "arm64" {
		return "arm64", nil
	} else {
		return "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}
}
