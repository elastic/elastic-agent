//go:build windows

package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
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

func printWindowsFileInfo(path string, logF loggerFunc) {

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION)
	if err != nil {
		panic(err)
	}

	logF("%s security descriptor: %v\n", path, sd)
}

func DumpFilesystemInfo(path string, logF loggerFunc) {
	stat, staterr := os.Stat(path)
	if staterr != nil {
		logF("Error stat()ing %s: %s\n", path, staterr)
	} else {
		logF("%s stat:\n%s\n", path, printFileInfo(stat))
		printWindowsFileInfo(path, logF)
	}
}
