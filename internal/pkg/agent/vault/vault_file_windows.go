// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package vault

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func (v *FileVault) encrypt(data []byte) ([]byte, error) {
	var out windows.DataBlob
	err := windows.CryptProtectData(newBlob(data), nil, newBlob(v.seed), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE, &out)
	if err != nil {
		return nil, err
	}
	result := make([]byte, out.Size)
	copy(result, unsafe.Slice(out.Data, out.Size))
	_, err = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (v *FileVault) decrypt(data []byte) ([]byte, error) {
	var out windows.DataBlob
	err := windows.CryptUnprotectData(newBlob(data), nil, newBlob(v.seed), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, err
	}

	result := make([]byte, out.Size)
	copy(result, unsafe.Slice(out.Data, out.Size))
	_, err = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	if err != nil {
		return nil, err
	}
	return result, nil
}

func tightenPermissions(path string, ownership utils.FileOwner) error {
	return perms.FixPermissions(path, perms.WithMask(0750), perms.WithOwnership(ownership))
}

func writeFile(fp string, data []byte) error {
	return os.WriteFile(fp, data, 0600)
}

func newBlob(d []byte) *windows.DataBlob {
	if len(d) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{
		Size: uint32(len(d)),
		Data: &d[0],
	}
}
