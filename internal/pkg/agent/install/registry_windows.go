// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	// UninstallKeyPath is the standard Windows registry path for Add/Remove Programs entries.
	UninstallKeyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

	elasticPublisher = "Elastic"
	elasticAgentURL  = "https://www.elastic.co/elastic-agent"
)

func agentUninstallKeyPath() string {
	return AgentUninstallKeyPathForNamespace(paths.InstallNamespace())
}

// AgentUninstallKeyPathForNamespace returns the full registry key path for the
// agent's Add/Remove Programs entry for the given namespace.
func AgentUninstallKeyPathForNamespace(namespace string) string {
	return UninstallKeyPath + `\` + paths.ServiceNameForNamespace(namespace)
}

// UpsertUninstallEntry creates or updates the entry under
// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall so that Elastic
// Agent appears in the Windows "Add or Remove Programs" list and exposes
// standard metadata (version, install date, publisher, uninstall command).
func UpsertUninstallEntry(topPath, displayVersion string) error {
	keyPath := agentUninstallKeyPath()
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.CREATE_SUB_KEY|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("creating uninstall registry key %q: %w", keyPath, err)
	}
	defer k.Close()

	agentBin := filepath.Join(topPath, paths.BinaryName)

	stringValues := []struct {
		name  string
		value string
	}{
		{"DisplayName", paths.ServiceDisplayName()},
		{"DisplayVersion", displayVersion},
		{"Publisher", elasticPublisher},
		// InstallDate uses the YYYYMMDD format required by Windows.
		{"InstallDate", time.Now().Format("20060102")},
		{"InstallLocation", topPath},
		// UninstallString is invoked when the user clicks "Uninstall" in the UI.
		{"UninstallString", fmt.Sprintf(`"%s" uninstall`, agentBin)},
		// QuietUninstallString is used for silent uninstalls (e.g. from scripts).
		{"QuietUninstallString", fmt.Sprintf(`"%s" uninstall --force`, agentBin)},
		{"URLInfoAbout", elasticAgentURL},
	}
	for _, sv := range stringValues {
		if err := k.SetStringValue(sv.name, sv.value); err != nil {
			return fmt.Errorf("setting registry value %q: %w", sv.name, err)
		}
	}

	// NoModify and NoRepair hide the "Change" and "Repair" buttons in the UI
	// since the agent does not support those operations through this entry.
	dwordValues := []struct {
		name  string
		value uint32
	}{
		{"NoModify", 1},
		{"NoRepair", 1},
	}
	for _, dv := range dwordValues {
		if err := k.SetDWordValue(dv.name, dv.value); err != nil {
			return fmt.Errorf("setting registry DWORD value %q: %w", dv.name, err)
		}
	}

	return nil
}

// RemoveUninstallEntry deletes the Elastic Agent entry from
// the Windows "Add or Remove Programs" list.
func RemoveUninstallEntry() error {
	keyPath := agentUninstallKeyPath()
	err := registry.DeleteKey(registry.LOCAL_MACHINE, keyPath)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("deleting uninstall registry key %q: %w", keyPath, err)
	}
	return nil
}

// RemoveMSIUninstallEntries removes Add/Remove Programs entries created by the
// MSI installer to avoid duplicates.
// See: https://github.com/elastic/elastic-stack-installers
func RemoveMSIUninstallEntries() error {
	guids := FindMSIProductCodes()
	for _, guid := range guids {
		if err := registry.DeleteKey(registry.LOCAL_MACHINE, UninstallKeyPath+`\`+guid); err != nil {
			return fmt.Errorf("deleting MSI uninstall registry key %q: %w", guid, err)
		}
	}
	return nil
}

// FindMSIProductCodes searches the Uninstall registry for MSI entries.
func FindMSIProductCodes() []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, UninstallKeyPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()

	return findMSIProductCodes(k)
}

// findMSIProductCodes enumerates the subkeys of the given open Uninstall key
// and returns the names of the Elastic Agent MSI entries.
func findMSIProductCodes(k registry.Key) []string {
	// Pass -1 to read all subkey names in a single call. Passing a positive
	// count (e.g. 100) does not paginate: ReadSubKeyNames always enumerates
	// from index 0 and returns a nil error whenever the key has at least that
	// many subkeys, so looping on a non-nil error spins forever on hosts with
	// many Add/Remove Programs entries.
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	var guids []string
	for _, name := range names {
		// The Elastic Agent MSI ProductCode varies per version but
		// it always starts with "{E550A894-5C44-5BEF-9967-".
		// See: https://github.com/elastic/elastic-stack-installers/blob/main/src/shared/Uuid5.cs
		if !strings.HasPrefix(strings.ToUpper(name), "{E550A894-5C44-5BEF-9967-") {
			continue
		}
		subKey, subErr := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if subErr != nil {
			continue
		}
		displayName, _, _ := subKey.GetStringValue("DisplayName")
		winInstaller, _, _ := subKey.GetIntegerValue("WindowsInstaller")
		subKey.Close()

		if strings.HasPrefix(displayName, "Elastic Agent") && winInstaller == 1 {
			guids = append(guids, name)
		}
	}
	return guids
}

// ConfigureRegistryPermissions sets the security descriptor for the uninstall registry key
//
// gives user the ability to update the registry entry, needed when installed with --unprivileged.
func ConfigureRegistryPermissions(ownership utils.FileOwner) error {
	keyPath := agentUninstallKeyPath()
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects
	sddl := "D:(A;;GA;;;SY)" + // SDDL_LOCAL_SYSTEM -> SDDL_GENERIC_ALL
		"(A;;GA;;;BA)" // SDDL_BUILTIN_ADMINISTRATORS -> SDDL_GENERIC_ALL
	if ownership.UID != "" {
		sddl += fmt.Sprintf("(A;;GRGWSD;;;%s)", ownership.UID) // Ownership UID -> SDDL_GENERIC_READ|SDDL_GENERIC_WRITE|SDDL_STANDARD_DELETE
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("building security descriptor for registry key %q: %w", keyPath, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("getting DACL from security descriptor: %w", err)
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, uint32(windows.READ_CONTROL|windows.WRITE_DAC))
	if err != nil {
		return fmt.Errorf("opening registry key %q for ACL update: %w", keyPath, err)
	}
	defer k.Close()
	return windows.SetSecurityInfo(windows.Handle(k), windows.SE_REGISTRY_KEY, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
