// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"strings"
	"syscall"
	"unsafe"
)

var (
	modkernel32            = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpaceEx = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procGetVolumePathName  = modkernel32.NewProc("GetVolumePathNameW")
)

func getAvailableDiskSpaceAt(dir string) (uint64, error) {
	dirPtr, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var available, total, totalFree uint64
	r1, _, err := procGetDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(dirPtr)),
		uintptr(unsafe.Pointer(&available)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r1 == 0 {
		// Call's err return value always holds the last error and is not
		// indicative of our call failing. Check return value for
		// success/failure
		return 0, err
	}
	return available, nil
}

func getVolumeNameAt(dir string) (string, error) {
	dirPtr, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return "", err
	}
	volumePath := make([]uint16, 32768)
	r1, _, err := procGetVolumePathName.Call(
		uintptr(unsafe.Pointer(dirPtr)),
		uintptr(unsafe.Pointer(&volumePath[0])),
		uintptr(len(volumePath)),
	)
	if r1 == 0 {
		return "", err
	}
	return strings.ToLower(syscall.UTF16ToString(volumePath)), nil
}
