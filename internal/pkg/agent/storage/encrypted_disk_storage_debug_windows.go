//go:build windows

package storage

import (
	"os"
	"syscall"
)

type loggerFunc func(fmtString string, args ...any)

func DumpFilesystemInfo(path string, logF loggerFunc) {
	stat, staterr := os.Stat(path)
	if staterr != nil {
		logF("Error stat()ing %s: %s", path, staterr)
	} else {
		logF("%s stat:\n%+v\n", path, stat)
		logF("%s win stat:\n%+v\n", path, stat.Sys().(*syscall.Win32FileAttributeData))
	}
}
