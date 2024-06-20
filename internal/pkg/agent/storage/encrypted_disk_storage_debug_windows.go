//go:build windows

package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	dumpSecurityDescriptor(path, logF)
	dumpSecurityDescriptor(filepath.Dir(path), logF)
}

func dumpSecurityDescriptor(path string, logF loggerFunc) {
	fileSD, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION)
	if err != nil {
		panic(fmt.Errorf("getting security descriptor for %s: %w", path, err))
	}

	logF("%s security descriptor: %s", path, fileSD)

	ownerSid, _, err := fileSD.Owner()
	if err != nil {
		panic(fmt.Errorf("getting owner from security descriptor %s: %w", fileSD, err))
	}

	account, domain, accType, err := ownerSid.LookupAccount("")
	if err != nil {
		panic(fmt.Errorf("looking up account for %s: %w", ownerSid, err))
	}

	logF("owner for %q: %s\\%s account type %x", path, domain, account, accType)
}

func DumpFilesystemInfo(path string, logF loggerFunc) {
	stat, staterr := os.Stat(path)
	if staterr != nil {
		logF("Error stat()ing %s: %s\n", path, staterr)
	} else {
		logF("%s stat:\n%s", path, printFileInfo(stat))
		printWindowsFileInfo(path, logF)
	}
}
