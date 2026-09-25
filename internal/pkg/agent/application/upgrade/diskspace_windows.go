// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func preallocateFile(file *os.File, size int64) error {
	if size > 0 {
		fileAllocationInfo := struct {
			AllocationSize int64
		}{
			AllocationSize: size,
		}
		buffer := (*byte)(unsafe.Pointer(&fileAllocationInfo))
		bufferSize := uint32(unsafe.Sizeof(fileAllocationInfo))

		if err := windows.SetFileInformationByHandle(
			windows.Handle(file.Fd()),
			windows.FileAllocationInfo,
			buffer,
			bufferSize,
		); err != nil {
			return err
		}
	}
	return nil
}

func getVolumeNameAt(dir string) (string, error) {
	dirPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", err
	}
	volumePath := make([]uint16, windows.MAX_LONG_PATH)
	if err := windows.GetVolumePathName(dirPtr, &volumePath[0], windows.MAX_LONG_PATH); err != nil {
		return "", err
	}
	return strings.ToLower(windows.UTF16ToString(volumePath)), nil
}

func getAvailableDiskSpaceAt(dir string) (uint64, error) {
	dirPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var available, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(dirPtr, &available, &total, &totalFree); err != nil {
		return 0, err
	}
	return available, nil
}
