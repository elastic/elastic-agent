// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package translate

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/elastic/beats/v7/pkg/config"
	"github.com/elastic/beats/v7/pkg/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths/pathstest"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func TestPersistentQueueDirectoryACL(t *testing.T) {
	pathstest.SetTop(t, t.TempDir())

	cfg := config.MustNewConfigFrom(`
hosts: ["localhost:9200"]
username: elastic
password: changeme
queue:
  persistent:
    file_storage:
      timeout: 1s
      max_size: 262144000
`)
	_, _, ext, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
	require.NoError(t, err)
	id := getFileStorageExtensionID("default").String()
	dir := ext[id].(map[string]any)["directory"].(string)

	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	require.NoError(t, err)
	allowed := []string{utils.SystemSID, utils.AdministratorSID, utils.InteractiveSID, user.User.Sid.String()}

	for _, path := range []string{dir, dir + `\compaction`} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		require.NoError(t, err)
		control, _, err := sd.Control()
		require.NoError(t, err)
		if path == dir {
			require.NotZero(t, control&windows.SE_DACL_PROTECTED, "DACL must not inherit from parent")
		}
		dacl, _, err := sd.DACL()
		require.NoError(t, err)
		require.NotNil(t, dacl)
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			require.NoError(t, windows.GetAce(dacl, i, &ace))
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
				continue
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
			require.Contains(t, allowed, sid, "unexpected ACE on %s", path)
		}
	}
}
