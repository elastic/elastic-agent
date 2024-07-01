//go:build !windows

package storage

import (
	"os"
)

type loggerFunc func(fmtString string, args ...any)

func DumpFilesystemInfo(path string, logF loggerFunc) {
	stat, staterr := os.Stat(path)
	if staterr != nil {
		logF("Error stat()ing %s: %s", path, staterr)
	} else {
		logF("%s stat:\n%+v\n", path, stat)
	}
}
