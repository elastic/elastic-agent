// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package vault

/*
#include <stdlib.h>

#include <Security/Security.h>

#cgo LDFLAGS: -framework Foundation -framework Security

extern OSStatus OpenKeychain(SecKeychainRef keychain);
extern OSStatus SetKeychainItem(SecKeychainRef keychain, const char *name, const char *key, const void *data, size_t len);
extern OSStatus GetKeychainItem(SecKeychainRef keychain, const char *name, const char *key, void **data, size_t *len);
extern OSStatus ExistsKeychainItem(SecKeychainRef keychain, const char *name, const char *key);
extern OSStatus RemoveKeychainItem(SecKeychainRef keychain, const char *name, const char *key);
extern char* GetOSStatusMessage(OSStatus status);

*/
import "C"
import (
	"fmt"
	"sync"
	"unsafe"
)

// Vault represents encrypted storage using the Darwin keychain.
type Vault struct {
	name     string
	keychain C.SecKeychainRef
	mx       sync.Mutex
}

// New initializes the vault store
// Call Close when done to release the resources
func New(name string, opts ...OptionFunc) (*Vault, error) {
	var keychain C.SecKeychainRef

	err := statusToError(C.OpenKeychain(keychain))
	if err != nil {
		return nil, fmt.Errorf("could not open keychain: %w", err)
	}

	return &Vault{
		name:     name,
		keychain: keychain,
	}, nil
}

// Close closes the vault store
func (v *Vault) Close() error {
	v.mx.Lock()
	defer v.mx.Unlock()

	if v.keychain != 0 {
		C.CFRelease(C.CFTypeRef(v.keychain))
		v.keychain = 0
	}
	return nil
}

// Set sets the key in the vault store
func (v *Vault) Set(key string, data []byte) error {
	v.mx.Lock()
	defer v.mx.Unlock()

	cname := C.CString(v.name)
	defer C.free(unsafe.Pointer(cname))

	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))

	cdata := C.CBytes(data)
	defer C.free(cdata)

	return statusToError(C.SetKeychainItem(v.keychain, cname, ckey, cdata, C.size_t(len(data))))
}

// Get retrieves the key from the vault store
func (v *Vault) Get(key string) ([]byte, error) {
	var (
		data unsafe.Pointer
		len  C.size_t
	)

	v.mx.Lock()
	defer v.mx.Unlock()

	cname := C.CString(v.name)
	defer C.free(unsafe.Pointer(cname))

	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))

	err := statusToError(C.GetKeychainItem(v.keychain, cname, ckey, &data, &len))
	if err != nil {
		return nil, err
	}
	b := C.GoBytes(data, C.int(len))
	C.free(data)
	return b, nil
}

// Exists checks if the key exists
func (v *Vault) Exists(key string) (bool, error) {
	v.mx.Lock()
	defer v.mx.Unlock()

	cname := C.CString(v.name)
	defer C.free(unsafe.Pointer(cname))

	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))

	status := C.ExistsKeychainItem(v.keychain, cname, ckey)
	if status == C.noErr {
		return true, nil
	}

	if status == C.errSecItemNotFound {
		return false, nil
	}
	return false, statusToError(status)
}

// Remove will remove a key from the keychain.
func (v *Vault) Remove(key string) error {
	v.mx.Lock()
	defer v.mx.Unlock()

	cname := C.CString(v.name)
	defer C.free(unsafe.Pointer(cname))

	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))

	return statusToError(C.RemoveKeychainItem(v.keychain, cname, ckey))
}

// statusToError converts OSStatus into Go error
func statusToError(status C.OSStatus) error {
	if status != C.noErr {
		cmsg := C.GetOSStatusMessage(status)
		msg := C.GoString(cmsg)
		C.free(unsafe.Pointer(cmsg))
		return &OSStatusError{
			status:  int(status),
			message: msg,
		}
	}
	return nil
}

// OSStatusError is an error type that can be returned by Darwin systems when interacting with the keychain.
type OSStatusError struct {
	status  int
	message string
}

func (o *OSStatusError) Error() string {
	return fmt.Sprintf("%d: %s", o.status, o.message)
}
