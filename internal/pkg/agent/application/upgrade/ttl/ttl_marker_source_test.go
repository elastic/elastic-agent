// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ttl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

// TestTTLMarkerRegistry_GetAll_PartialReturnsMalformedAlongsideParsed proves
// that GetAll keeps returning successfully parsed entries even when a sibling
// .ttl file is unparseable, and surfaces the broken entry via the malformed
// map instead of discarding the whole read. This is the contract cleanupAgentDirectories
// relies on to preserve recoverable installs whose metadata got corrupted.
func TestTTLMarkerRegistry_GetAll_PartialReturnsMalformedAlongsideParsed(t *testing.T) {
	tmpDir := t.TempDir()
	goodHome := filepath.Join("data", "elastic-agent-1.2.3-good")
	badHome := filepath.Join("data", "elastic-agent-9.9.9-corrupt")

	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, goodHome), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, badHome), 0755))

	validUntil := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	goodMarker := strings.TrimSpace(fmt.Sprintf(
		"version: 1.2.3\nvalid_until: %s",
		validUntil.Format(time.RFC3339),
	))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, goodHome, ttlMarkerName), []byte(goodMarker), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, badHome, ttlMarkerName), []byte("this is not yaml"), 0644))

	testLogger, _ := loggertest.New(t.Name())
	T := NewTTLMarkerRegistry(testLogger, tmpDir)

	markers, malformed, err := T.GetAll()
	require.NoError(t, err, "GetAll should not return a structural error here")

	assert.Len(t, markers, 1, "expected exactly one parsed marker")
	if assert.Contains(t, markers, goodHome) {
		assert.Equal(t, "1.2.3", markers[goodHome].Version)
		assert.True(t, markers[goodHome].ValidUntil.Equal(validUntil), "ValidUntil mismatch")
	}

	assert.Len(t, malformed, 1, "expected exactly one malformed entry")
	if assert.Contains(t, malformed, badHome) {
		assert.Error(t, malformed[badHome])
	}
}

func TestTTLMarkerRegistry_Set(t *testing.T) {
	const TTLMarkerYAMLTemplate = `
        version: {{ .Version }}
        hash: {{ .Hash }}
        valid_until: {{ .ValidUntil }}`

	expectedMarkerContentTemplate, err := template.New("expected marker").Parse(TTLMarkerYAMLTemplate)
	require.NoError(t, err)

	now := time.Now()
	nowString := now.Format(time.RFC3339)
	// re-parse now to account for loss of fidelity due to marshal/unmarshal
	now, _ = time.Parse(time.RFC3339, nowString)

	tomorrow := now.Add(24 * time.Hour)
	tomorrowString := tomorrow.Format(time.RFC3339)
	tomorrow, _ = time.Parse(time.RFC3339, tomorrowString)

	versions := []string{"1.2.3", "4.5.6"}
	versionedHomes := []string{"elastic-agent-1.2.3-past", "elastic-agent-4.5.6-present"}
	hashes := []string{"past", "present"}
	ttls := []string{tomorrowString, ""}

	type args struct {
		m map[string]TTLMarker
	}
	tests := []struct {
		name           string
		setup          func(t *testing.T, tmpDir string)
		args           args
		wantErr        assert.ErrorAssertionFunc
		postAssertions func(t *testing.T, tmpDir string)
	}{
		{
			name: "no ttl are present - all get created",
			setup: func(t *testing.T, tmpDir string) {
				for _, versionedHome := range versionedHomes {
					err := os.MkdirAll(filepath.Join(tmpDir, "data", versionedHome), 0755)
					require.NoError(t, err, "error setting up fake agent install directory")
				}
			},
			args: args{
				map[string]TTLMarker{
					filepath.Join("data", versionedHomes[0]): {
						Version:    versions[0],
						Hash:       hashes[0],
						ValidUntil: tomorrow,
					},
				},
			},
			wantErr: assert.NoError,
			postAssertions: func(t *testing.T, tmpDir string) {
				notExistingTTLMarkerFilePath := filepath.Join(tmpDir, "data", versionedHomes[1], ttlMarkerName)
				assert.NoFileExists(t, notExistingTTLMarkerFilePath)
				expectedTTLMarkerFilePath := filepath.Join(tmpDir, "data", versionedHomes[0], ttlMarkerName)
				if assert.FileExists(t, expectedTTLMarkerFilePath, "new TTL marker should have been created") {

					b := new(strings.Builder)
					err = expectedMarkerContentTemplate.Execute(b, map[string]string{"Version": versions[0], "ValidUntil": ttls[0], "Hash": hashes[0]})
					require.NoError(t, err)
					actualMarkerContent, err := os.ReadFile(expectedTTLMarkerFilePath)
					require.NoError(t, err)
					assert.YAMLEq(t, b.String(), string(actualMarkerContent))
				}
			},
		},
		{
			name: "ttls are present, none are specified - all deleted",
			setup: func(t *testing.T, tmpDir string) {
				for i, versionedHome := range versionedHomes {
					err = os.MkdirAll(filepath.Join(tmpDir, "data", versionedHome), 0755)
					require.NoError(t, err, "error setting up fake agent install directory")
					b := new(strings.Builder)
					err = expectedMarkerContentTemplate.Execute(b, map[string]string{"Version": versions[i], "ValidUntil": ttls[i], "Hash": hashes[i]})
					require.NoError(t, err, "error setting up ttl marker")
					err = os.WriteFile(filepath.Join(tmpDir, "data", versionedHomes[i], ttlMarkerName), []byte(b.String()), 0644)
				}
			},
			args: args{
				nil,
			},
			wantErr: assert.NoError,
			postAssertions: func(t *testing.T, tmpDir string) {
				for _, versionedHome := range versionedHomes {
					notExistingTTLMarkerFilePath := filepath.Join(tmpDir, "data", versionedHome, ttlMarkerName)
					assert.NoFileExists(t, notExistingTTLMarkerFilePath)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, tmpDir)
			}
			testLogger, _ := loggertest.New(t.Name())
			T := NewTTLMarkerRegistry(testLogger, tmpDir)
			tt.wantErr(t, T.Set(tt.args.m), fmt.Sprintf("Set(%v)", tt.args.m))
			if tt.postAssertions != nil {
				tt.postAssertions(t, tmpDir)
			}
		})
	}
}

// TestTTLMarkerRegistry_Set_TolerateMalformedExisting proves that Set no
// longer aborts when an existing .ttl file holds a corrupt payload that
// cannot be parsed as YAML, so a single bad marker on disk cannot wedge
// subsequent upgrade and rollback cycles.
func TestTTLMarkerRegistry_Set_TolerateMalformedExisting(t *testing.T) {
	const corruptPayload = "not valid yaml: {"

	const markerYAMLTemplate = `
        version: {{ .Version }}
        hash: {{ .Hash }}
        valid_until: {{ .ValidUntil }}`

	markerTpl, err := template.New("marker").Parse(markerYAMLTemplate)
	require.NoError(t, err)

	tomorrowString := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	tomorrow, err := time.Parse(time.RFC3339, tomorrowString)
	require.NoError(t, err)

	homeA := filepath.Join("data", "elastic-agent-1.2.3-a")
	homeB := filepath.Join("data", "elastic-agent-4.5.6-b")
	homeC := filepath.Join("data", "elastic-agent-7.8.9-c")

	renderMarker := func(t *testing.T, version, hash, validUntil string) string {
		t.Helper()
		b := new(strings.Builder)
		require.NoError(t, markerTpl.Execute(b, map[string]string{
			"Version":    version,
			"Hash":       hash,
			"ValidUntil": validUntil,
		}))
		return b.String()
	}

	t.Run("corrupt live ttl is overwritten when desired state includes it", func(t *testing.T) {
		tmpDir := t.TempDir()
		for _, home := range []string{homeA, homeB, homeC} {
			require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, home), 0755))
		}

		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, homeA, ttlMarkerName), []byte(corruptPayload), 0644))
		require.NoError(t, os.WriteFile(
			filepath.Join(tmpDir, homeB, ttlMarkerName),
			[]byte(renderMarker(t, "4.5.6", "bbbbbb", tomorrowString)),
			0644,
		))

		desired := map[string]TTLMarker{
			homeA: {Version: "1.2.3", Hash: "aaaaaa", ValidUntil: tomorrow},
			homeC: {Version: "7.8.9", Hash: "cccccc", ValidUntil: tomorrow},
		}

		testLogger, _ := loggertest.New(t.Name())
		T := NewTTLMarkerRegistry(testLogger, tmpDir)
		require.NoError(t, T.Set(desired))

		aPath := filepath.Join(tmpDir, homeA, ttlMarkerName)
		if assert.FileExists(t, aPath, "corrupt marker should have been overwritten with valid YAML") {
			got, readErr := readTTLMarker(aPath)
			require.NoError(t, readErr, "rewritten marker must parse")
			assert.Equal(t, "1.2.3", got.Version)
			assert.Equal(t, "aaaaaa", got.Hash)
			assert.True(t, got.ValidUntil.Equal(tomorrow), "ValidUntil mismatch")
		}

		assert.NoFileExists(t, filepath.Join(tmpDir, homeB, ttlMarkerName), "B was not in desired state and should have been swept")

		cPath := filepath.Join(tmpDir, homeC, ttlMarkerName)
		if assert.FileExists(t, cPath) {
			got, readErr := readTTLMarker(cPath)
			require.NoError(t, readErr)
			assert.Equal(t, "7.8.9", got.Version)
			assert.Equal(t, "cccccc", got.Hash)
			assert.True(t, got.ValidUntil.Equal(tomorrow), "ValidUntil mismatch")
		}
	})

	// Set(nil) is the rollback path called from rollbackInstall: a corrupt
	// marker on disk must not block the rollback that recovers from a failed
	// upgrade, otherwise the broken state is sticky.
	t.Run("Set(nil) sweeps a malformed live ttl", func(t *testing.T) {
		tmpDir := t.TempDir()
		for _, home := range []string{homeA, homeB} {
			require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, home), 0755))
		}

		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, homeA, ttlMarkerName), []byte(corruptPayload), 0644))
		require.NoError(t, os.WriteFile(
			filepath.Join(tmpDir, homeB, ttlMarkerName),
			[]byte(renderMarker(t, "4.5.6", "bbbbbb", tomorrowString)),
			0644,
		))

		testLogger, _ := loggertest.New(t.Name())
		T := NewTTLMarkerRegistry(testLogger, tmpDir)
		require.NoError(t, T.Set(nil))

		assert.NoFileExists(t, filepath.Join(tmpDir, homeA, ttlMarkerName))
		assert.NoFileExists(t, filepath.Join(tmpDir, homeB, ttlMarkerName))
	})

	t.Run("malformed existing is reaped when desired targets a different home", func(t *testing.T) {
		tmpDir := t.TempDir()
		for _, home := range []string{homeA, homeC} {
			require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, home), 0755))
		}

		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, homeA, ttlMarkerName), []byte(corruptPayload), 0644))

		desired := map[string]TTLMarker{
			homeC: {Version: "7.8.9", Hash: "cccccc", ValidUntil: tomorrow},
		}

		testLogger, _ := loggertest.New(t.Name())
		T := NewTTLMarkerRegistry(testLogger, tmpDir)
		require.NoError(t, T.Set(desired))

		assert.NoFileExists(t, filepath.Join(tmpDir, homeA, ttlMarkerName), "malformed marker outside desired set must be removed")

		cPath := filepath.Join(tmpDir, homeC, ttlMarkerName)
		if assert.FileExists(t, cPath) {
			got, readErr := readTTLMarker(cPath)
			require.NoError(t, readErr)
			assert.Equal(t, "7.8.9", got.Version)
		}
	})
}
