//go:build windows

package upgrade

import winSys "golang.org/x/sys/windows"

var TestErrors = []error{
	winSys.ERROR_DISK_FULL,
	winSys.ERROR_HANDLE_DISK_FULL,
}
