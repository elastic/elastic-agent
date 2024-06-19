//go:build windows

package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type loggerFunc func(fmtString string, args ...any)

func printFileInfo(info os.FileInfo) string {
	buf := new(strings.Builder)
	encoder := json.NewEncoder(buf)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(info)
	if err != nil {
		return fmt.Sprintf("error encoding FileInfo: %s", err)
	}
	return buf.String()
}

func DumpFilesystemInfo(path string, logF loggerFunc) {
	stat, staterr := os.Stat(path)
	if staterr != nil {
		logF("Error stat()ing %s: %s", path, staterr)
	} else {
		logF("%s stat:\n%s\n", path, printFileInfo(stat))
	}
}
