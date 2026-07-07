// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package install

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

// newTestUninstallKey creates a temporary, isolated key under HKCU that
// mimics the Uninstall key structure, populated with the requested number of
// non-MSI filler subkeys. It returns the open key; cleanup is registered via
// t.Cleanup.
func newTestUninstallKey(t *testing.T, fillerSubKeys int) registry.Key {
	t.Helper()

	// Use a unique path under HKCU so tests don't require admin rights and
	// don't collide with real Add/Remove Programs entries.
	root := fmt.Sprintf(`Software\ElasticAgentTest\%d\Uninstall`, time.Now().UnixNano())
	k, _, err := registry.CreateKey(registry.CURRENT_USER, root, registry.CREATE_SUB_KEY|registry.ENUMERATE_SUB_KEYS)
	require.NoError(t, err)

	t.Cleanup(func() {
		// Best-effort recursive cleanup of the test tree.
		_ = deleteKeyRecursive(registry.CURRENT_USER, root)
		k.Close()
	})

	for i := 0; i < fillerSubKeys; i++ {
		sub, _, err := registry.CreateKey(k, fmt.Sprintf("filler-%d", i), registry.SET_VALUE)
		require.NoError(t, err)
		sub.Close()
	}

	return k
}

// addMSIEntry creates a subkey under k that looks like an Elastic Agent MSI
// Add/Remove Programs entry.
func addMSIEntry(t *testing.T, k registry.Key, guid string) {
	t.Helper()
	sub, _, err := registry.CreateKey(k, guid, registry.SET_VALUE)
	require.NoError(t, err)
	defer sub.Close()
	require.NoError(t, sub.SetStringValue("DisplayName", "Elastic Agent"))
	require.NoError(t, sub.SetDWordValue("WindowsInstaller", 1))
}

func deleteKeyRecursive(root registry.Key, path string) error {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return err
	}
	names, _ := k.ReadSubKeyNames(-1)
	k.Close()
	for _, name := range names {
		_ = deleteKeyRecursive(root, path+`\`+name)
	}
	return registry.DeleteKey(root, path)
}

// TestFindMSIProductCodesManySubKeys is a regression test for the infinite
// loop that occurred when the Uninstall key had >=100 subkeys. With the old
// ReadSubKeyNames(100) pagination bug this test would hang forever.
func TestFindMSIProductCodesManySubKeys(t *testing.T) {
	const guid = "{E550A894-5C44-5BEF-9967-0123456789AB}"

	// 150 filler subkeys (well over the 100 threshold) plus one real MSI entry.
	k := newTestUninstallKey(t, 150)
	addMSIEntry(t, k, guid)

	done := make(chan []string, 1)
	go func() {
		done <- findMSIProductCodes(k)
	}()

	select {
	case guids := <-done:
		require.Equal(t, []string{guid}, guids)
	case <-time.After(30 * time.Second):
		t.Fatal("findMSIProductCodes did not return; likely stuck in the pagination loop")
	}
}

// TestFindMSIProductCodesFewSubKeys verifies the function still works when the
// key has fewer than 100 subkeys (the previously-working path).
func TestFindMSIProductCodesFewSubKeys(t *testing.T) {
	const guid = "{E550A894-5C44-5BEF-9967-FEDCBA987654}"

	k := newTestUninstallKey(t, 5)
	addMSIEntry(t, k, guid)

	require.Equal(t, []string{guid}, findMSIProductCodes(k))
}

// TestFindMSIProductCodesNoMatches verifies non-Elastic entries are ignored.
func TestFindMSIProductCodesNoMatches(t *testing.T) {
	k := newTestUninstallKey(t, 120)
	require.Empty(t, findMSIProductCodes(k))
}
