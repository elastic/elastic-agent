//go:build !darwin

package vault

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDarwinKeyChainVault_Close(t *testing.T) {
	dkcv := new(DarwinKeyChainVault)
	err := dkcv.Close()
	assert.ErrorIs(t, err, ErrorImplementationNotAvailable, "when not running in darwin we cannot call any function on a keychain vault")
}

func TestDarwinKeyChainVault_Exists(t *testing.T) {
	dkcv := new(DarwinKeyChainVault)
	exists, err := dkcv.Exists(context.TODO(), "key")
	assert.False(t, exists, "when not running in darwin we cannot call any function on a keychain vault")
	assert.ErrorIs(t, err, ErrorImplementationNotAvailable, "when not running in darwin we cannot call any function on a keychain vault")
}

func TestDarwinKeyChainVault_Get(t *testing.T) {
	dkcv := new(DarwinKeyChainVault)
	keyBytes, err := dkcv.Get(context.TODO(), "key")
	assert.Nil(t, keyBytes, "when not running in darwin we cannot call any function on a keychain vault")
	assert.ErrorIs(t, err, ErrorImplementationNotAvailable, "when not running in darwin we cannot call any function on a keychain vault")
}

func TestDarwinKeyChainVault_Remove(t *testing.T) {
	dkcv := new(DarwinKeyChainVault)
	err := dkcv.Remove(context.TODO(), "key")
	assert.ErrorIs(t, err, ErrorImplementationNotAvailable, "when not running in darwin we cannot call any function on a keychain vault")
}

func TestDarwinKeyChainVault_Set(t *testing.T) {
	dkcv := new(DarwinKeyChainVault)
	err := dkcv.Set(context.TODO(), "key", []byte("data"))
	assert.ErrorIs(t, err, ErrorImplementationNotAvailable, "when not running in darwin we cannot call any function on a keychain vault")
}

func TestNewDarwinKeyChainVault(t *testing.T) {
	v, err := NewDarwinKeyChainVault(context.TODO(), Options{})
	assert.Nil(t, v, "when not running in darwin we cannot instantiate a keychain vault")
	assert.ErrorIs(t, err, ErrorImplementationNotAvailable, "when not running in darwin we cannot instantiate a keychain vault")
}
