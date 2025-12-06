// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ttl

import (
	"bytes"
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

func TestTTLMarkerRegistry_Get(t *testing.T) {
	const TTLMarkerYAMLTemplate = `
        version: {{ .Version }}
        valid_until: {{ .ValidUntil }}`

	parsedTemplate, err := template.New("ttlMarker").Parse(TTLMarkerYAMLTemplate)
	require.NoError(t, err, "error parsing ttl marker template")

	now := time.Now()
	nowString := now.Format(time.RFC3339)
	// re-parse now to account for loss of fidelity due to marshal/unmarshal
	now, _ = time.Parse(time.RFC3339, nowString)

	yesterday := now.Add(-24 * time.Hour)
	yesterdayString := yesterday.Format(time.RFC3339)

	tomorrow := now.Add(24 * time.Hour)
	tomorrowString := tomorrow.Format(time.RFC3339)

	versions := []string{"1.2.3", "4.5.6", "7.8.9-SNAPSHOT"}
	versionedHomes := []string{"elastic-agent-1.2.3-past", "elastic-agent-4.5.6-present", "elastic-agent-7.8.9-SNAPSHOT-future"}
	ttls := []string{yesterdayString, nowString, tomorrowString}

	tests := []struct {
		name    string
		setup   func(t *testing.T, tmpDir string)
		want    map[string]TTLMarker
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "Empty directory - empty map",
			setup: func(t *testing.T, tmpDir string) {
				// nothing to do here
			},
			want:    map[string]TTLMarker{},
			wantErr: assert.NoError,
		},
		{
			name: "multiple directories, no marker - empty map",
			setup: func(t *testing.T, tmpDir string) {
				for _, versionedHome := range versionedHomes {
					err := os.MkdirAll(filepath.Join(tmpDir, "data", versionedHome), 0755)
					require.NoError(t, err, "error setting up fake agent install directory")
				}
			},
			want:    map[string]TTLMarker{},
			wantErr: assert.NoError,
		},
		{
			name: "multiple directories, ttl on past and present marker - return value",
			setup: func(t *testing.T, tmpDir string) {

				for i, versionedHome := range versionedHomes {
					err := os.MkdirAll(filepath.Join(tmpDir, "data", versionedHome), 0755)
					require.NoError(t, err, "error setting up fake agent install directory")

					if i < 2 {
						buf := bytes.Buffer{}
						err = parsedTemplate.Execute(&buf, map[string]string{"Version": versions[i], "ValidUntil": ttls[i]})
						require.NoError(t, err, "error executing ttl marker template")
						err = os.WriteFile(filepath.Join(tmpDir, "data", versionedHome, ttlMarkerName), buf.Bytes(), 0644)
						require.NoError(t, err, "error setting up fake agent ttl marker")
					}
				}
			},
			want: map[string]TTLMarker{
				filepath.Join("data", "elastic-agent-1.2.3-past"): {
					Version:    "1.2.3",
					ValidUntil: yesterday,
				},
				filepath.Join("data", "elastic-agent-4.5.6-present"): {
					Version:    "4.5.6",
					ValidUntil: now,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "empty marker - error",
			setup: func(t *testing.T, tmpDir string) {
				for _, versionedHome := range versionedHomes {
					err := os.MkdirAll(filepath.Join(tmpDir, "data", versionedHome), 0755)
					require.NoError(t, err, "error setting up fake agent install directory")
					err = os.WriteFile(filepath.Join(tmpDir, "data", versionedHome, ttlMarkerName), nil, 0644)
					require.NoError(t, err, "error setting up fake agent ttl marker")
				}
			},
			want:    nil,
			wantErr: assert.Error,
		},
		{
			name: "ttl content is not yaml - error",
			setup: func(t *testing.T, tmpDir string) {
				err := os.MkdirAll(filepath.Join(tmpDir, "data", versionedHomes[0]), 0755)
				require.NoError(t, err, "error setting up fake agent install directory")
				err = os.WriteFile(filepath.Join(tmpDir, "data", versionedHomes[0], ttlMarkerName), []byte("this is not yaml"), 0644)
				require.NoError(t, err, "error setting up fake agent ttl marker")
			},
			want:    nil,
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tt.setup(t, tmpDir)
			testLogger, _ := loggertest.New(t.Name())
			T := NewTTLMarkerRegistry(testLogger, tmpDir)
			got, err := T.Get()
			if !tt.wantErr(t, err, "Get()") {
				return
			}
			assert.Equal(t, tt.want, got, "Get()")
		})
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
