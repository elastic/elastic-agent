// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
)

func TestFileDescriptorSource_AddInstallDesc(t *testing.T) {
	testcases := []struct {
		name             string
		setupDir         func(t *testing.T, tmpDir string) string
		arg              v1.AgentInstallDesc
		expected         *v1.InstallDescriptor
		wantErr          assert.ErrorAssertionFunc
		postOpAssertions func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor)
	}{
		{
			name: "no existing file, adding a descriptor creates the file and returns the updated descriptor",
			arg: v1.AgentInstallDesc{
				Version:       "1.2.3",
				Hash:          "abcdef",
				VersionedHome: "date/elastic-agent-1.2.3-abcdef",
				Flavor:        "basic",
				Active:        true,
			},
			expected: createInstallDescriptor([]v1.AgentInstallDesc{
				{
					Version:       "1.2.3",
					Hash:          "abcdef",
					VersionedHome: "date/elastic-agent-1.2.3-abcdef",
					Flavor:        "basic",
					Active:        true,
				},
			}),
			wantErr: assert.NoError,
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				checkInstallDescriptorMatches(t, filepath.Join(tmpDir, installMarker), actual)
			},
		},
		{
			name: "existing empty file, adding a descriptor updates the file and returns the updated descriptor",
			setupDir: func(t *testing.T, tmpDir string) string {
				markerFileName := "emptydescriptor.yaml"
				err := os.WriteFile(filepath.Join(tmpDir, markerFileName), nil, 0o644)
				require.NoError(t, err)
				return markerFileName
			},
			arg: v1.AgentInstallDesc{
				Version:       "1.2.3",
				Hash:          "abcdef",
				VersionedHome: "date/elastic-agent-1.2.3-abcdef",
				Flavor:        "basic",
				Active:        true,
			},
			expected: createInstallDescriptor([]v1.AgentInstallDesc{
				{
					Version:       "1.2.3",
					Hash:          "abcdef",
					VersionedHome: "date/elastic-agent-1.2.3-abcdef",
					Flavor:        "basic",
					Active:        true,
				},
			}),
			wantErr: assert.NoError,
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				checkInstallDescriptorMatches(t, filepath.Join(tmpDir, installMarker), actual)
			},
		},
		{
			name: "existing file with another install descriptor, adding a descriptor updates the file and the descriptor",
			setupDir: func(t *testing.T, tmpDir string) string {
				markerFileName := "filleddescriptor.yaml"
				descriptor := v1.NewInstallDescriptor()
				descriptor.AgentInstalls = []v1.AgentInstallDesc{
					{
						OptionalTTLItem: v1.OptionalTTLItem{},
						Version:         "0.0.0",
						Hash:            "oooooo",
						VersionedHome:   "date/elastic-agent-0.0.0-oooooo",
						Flavor:          "oooo",
						Active:          false,
					},
				}

				buf := new(bytes.Buffer)
				err := v1.WriteInstallDescriptor(buf, descriptor)
				require.NoError(t, err, "error writing install descriptor during setup")

				outfilePath := filepath.Join(tmpDir, markerFileName)
				err = os.WriteFile(outfilePath, buf.Bytes(), 0o644)
				require.NoError(t, err, "error writing output file %s", markerFileName)

				return markerFileName
			},
			arg: v1.AgentInstallDesc{
				Version:       "1.2.3",
				Hash:          "abcdef",
				VersionedHome: "date/elastic-agent-1.2.3-abcdef",
				Flavor:        "basic",
				Active:        true,
			},
			expected: createInstallDescriptor([]v1.AgentInstallDesc{
				{
					Version:       "1.2.3",
					Hash:          "abcdef",
					VersionedHome: "date/elastic-agent-1.2.3-abcdef",
					Flavor:        "basic",
					Active:        true,
				},
				{
					Version:       "0.0.0",
					Hash:          "oooooo",
					VersionedHome: "date/elastic-agent-0.0.0-oooooo",
					Flavor:        "oooo",
					Active:        false,
				},
			}),
			wantErr: assert.NoError,
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				checkInstallDescriptorMatches(t, filepath.Join(tmpDir, installMarker), actual)
			},
		},
		{
			name: "existing malformed install descriptor, adding a descriptor returns error",
			setupDir: func(t *testing.T, tmpDir string) string {

				markerFileName := "malformeddescriptor"
				outfilePath := filepath.Join(tmpDir, markerFileName)
				err := os.WriteFile(outfilePath, []byte("malformed (non-YAML) content"), 0o644)
				require.NoError(t, err, "error creating output file %s", markerFileName)

				return markerFileName
			},
			arg: v1.AgentInstallDesc{
				Version:       "1.2.3",
				Hash:          "abcdef",
				VersionedHome: "date/elastic-agent-1.2.3-abcdef",
				Flavor:        "basic",
				Active:        true,
			},
			expected: nil,
			wantErr:  assert.Error,
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				markerAbsPath := filepath.Join(tmpDir, installMarker)
				assert.FileExists(t, markerAbsPath, "install descriptor exists at %s", installMarker)
				fileContent, err := os.ReadFile(markerAbsPath)
				require.NoError(t, err, "error reading file %s", markerAbsPath)
				assert.Equal(t, []byte("malformed (non-YAML) content"), fileContent, "install descriptor content should be left untouched")
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			installMarkerFile := paths.MarkerFileName
			if tc.setupDir != nil {
				installMarkerFile = tc.setupDir(t, tmpDir)
			}

			src := NewFileDescriptorSource(filepath.Join(tmpDir, installMarkerFile))

			installDescriptor, err := src.AddInstallDesc(tc.arg)
			tc.wantErr(t, err)
			assert.Equal(t, tc.expected, installDescriptor)

			if tc.postOpAssertions != nil {
				tc.postOpAssertions(t, tmpDir, installMarkerFile, installDescriptor)
			}
		})
	}
}

func TestFileDescriptorSource_ModifyInstallDesc(t *testing.T) {
	// useful variables for testcases
	aMomentInTime := time.Now()
	modifierFunctionError := errors.New("whoops! don't trust modifier functions")
	calledModifierFunctionError := errors.New("this should not have been invoked")

	testcases := []struct {
		name             string
		setupDir         func(t *testing.T, tmpDir string) string
		arg              func(desc *v1.AgentInstallDesc) error
		expected         *v1.InstallDescriptor
		wantErr          assert.ErrorAssertionFunc
		postOpAssertions func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor)
	}{
		{
			name: "no existing file, modifying a descriptor returns error",
			arg: func(desc *v1.AgentInstallDesc) error {
				return calledModifierFunctionError
			},
			expected: nil,
			wantErr:  assert.Error,
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				assert.NoFileExists(t, filepath.Join(tmpDir, installMarker), "install descriptor should not exist at %s", installMarker)
			},
		},
		{
			name: "empty file, modifying a descriptor returns error",
			setupDir: func(t *testing.T, tmpDir string) string {
				markerFileName := "emptydescriptor.yaml"
				err := os.WriteFile(filepath.Join(tmpDir, markerFileName), nil, 0o644)
				require.NoError(t, err, "error creating output file %s", markerFileName)
				return markerFileName
			},
			arg: func(desc *v1.AgentInstallDesc) error {
				return calledModifierFunctionError
			},
			expected: nil,
			wantErr:  assert.Error,
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				assert.FileExists(t, filepath.Join(tmpDir, installMarker), "install descriptor should not exist at %s", installMarker)
				fileContent, err := os.ReadFile(filepath.Join(tmpDir, installMarker))
				assert.NoError(t, err, "error reading file %s", installMarker)
				assert.Empty(t, fileContent, "install descriptor content should be empty")
			},
		},
		{
			name: "empty descriptor (not file), modifying a descriptor does not call modifier function",
			setupDir: func(t *testing.T, tmpDir string) string {
				installDescriptor := v1.NewInstallDescriptor()
				buf := new(bytes.Buffer)
				err := v1.WriteInstallDescriptor(buf, installDescriptor)
				require.NoError(t, err, "error writing install descriptor during setup")

				markerFileName := "zerodescriptor.yaml"
				err = os.WriteFile(filepath.Join(tmpDir, markerFileName), buf.Bytes(), 0o644)
				require.NoError(t, err, "error creating output file %s", markerFileName)
				return markerFileName
			},
			arg: func(desc *v1.AgentInstallDesc) error {
				return calledModifierFunctionError
			},
			expected: createInstallDescriptor(nil),
			wantErr:  assert.NoError,
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				checkInstallDescriptorMatches(t, filepath.Join(tmpDir, installMarker), actual)
			},
		},
		{
			name: " valid descriptor with multiple installs, modifying a descriptor call modifier function on all installs",
			setupDir: func(t *testing.T, tmpDir string) string {
				markerFileName := "descriptor.yaml"
				installDescriptor := createInstallDescriptor([]v1.AgentInstallDesc{
					{
						Version:       "4.5.6",
						Hash:          "ghijkl",
						VersionedHome: "date/elastic-agent-4.5.6-ghijkl",
						Flavor:        "basic",
						Active:        false,
					},
					{
						Version:       "1.2.3",
						Hash:          "abcdef",
						VersionedHome: "date/elastic-agent-1.2.3-abcdef",
						Flavor:        "basic",
						Active:        true,
					},
					{
						Version:       "0.0.0",
						Hash:          "oooooo",
						VersionedHome: "date/elastic-agent-0.0.0-oooooo",
						Flavor:        "oooo",
						Active:        false,
					},
				})

				buf := new(bytes.Buffer)
				err := v1.WriteInstallDescriptor(buf, installDescriptor)
				require.NoError(t, err, "error writing install descriptor during setup")

				err = os.WriteFile(filepath.Join(tmpDir, markerFileName), buf.Bytes(), 0o644)
				require.NoError(t, err, "error creating output file %s", markerFileName)

				return markerFileName
			},
			arg: func(desc *v1.AgentInstallDesc) error {
				// make version 4.5.6 active and all others inactive
				if desc.Version == "4.5.6" {
					desc.Active = true
				} else {
					desc.Active = false
					desc.TTL = &aMomentInTime
				}

				return nil
			},
			expected: createInstallDescriptor([]v1.AgentInstallDesc{
				{
					Version:       "4.5.6",
					Hash:          "ghijkl",
					VersionedHome: "date/elastic-agent-4.5.6-ghijkl",
					Flavor:        "basic",
					Active:        true,
				},
				{
					Version:       "1.2.3",
					Hash:          "abcdef",
					VersionedHome: "date/elastic-agent-1.2.3-abcdef",
					Flavor:        "basic",
					Active:        false,
					OptionalTTLItem: v1.OptionalTTLItem{
						TTL: &aMomentInTime,
					},
				},
				{
					Version:       "0.0.0",
					Hash:          "oooooo",
					VersionedHome: "date/elastic-agent-0.0.0-oooooo",
					Flavor:        "oooo",
					Active:        false,
					OptionalTTLItem: v1.OptionalTTLItem{
						TTL: &aMomentInTime,
					},
				},
			}),
			wantErr: assert.NoError,
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				checkInstallDescriptorMatches(t, filepath.Join(tmpDir, installMarker), actual)
			},
		},
		{
			name: " valid descriptor with installs, returns error if modifier function errors out and leaves the file untouched",
			setupDir: func(t *testing.T, tmpDir string) string {
				markerFileName := "descriptor.yaml"
				installDescriptor := createInstallDescriptor([]v1.AgentInstallDesc{
					{
						Version:       "1.2.3",
						Hash:          "abcdef",
						VersionedHome: "date/elastic-agent-1.2.3-abcdef",
						Flavor:        "basic",
						Active:        true,
					},
					{
						Version:       "0.0.0",
						Hash:          "oooooo",
						VersionedHome: "date/elastic-agent-0.0.0-oooooo",
						Flavor:        "oooo",
						Active:        false,
					},
				})

				buf := new(bytes.Buffer)
				err := v1.WriteInstallDescriptor(buf, installDescriptor)
				require.NoError(t, err, "error writing install descriptor during setup")

				err = os.WriteFile(filepath.Join(tmpDir, markerFileName), buf.Bytes(), 0o644)
				require.NoError(t, err, "error creating output file %s", markerFileName)
				return markerFileName
			},
			arg: func(desc *v1.AgentInstallDesc) error {
				// modify flavor and then return error
				desc.Flavor = "touched"
				return modifierFunctionError
			},
			expected: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, modifierFunctionError, i)
			},
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				untouchedDescriptor := createInstallDescriptor([]v1.AgentInstallDesc{
					{
						Version:       "1.2.3",
						Hash:          "abcdef",
						VersionedHome: "date/elastic-agent-1.2.3-abcdef",
						Flavor:        "basic",
						Active:        true,
					},
					{
						Version:       "0.0.0",
						Hash:          "oooooo",
						VersionedHome: "date/elastic-agent-0.0.0-oooooo",
						Flavor:        "oooo",
						Active:        false,
					},
				})
				checkInstallDescriptorMatches(t, filepath.Join(tmpDir, installMarker), untouchedDescriptor)
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			installMarkerFile := paths.MarkerFileName
			if tc.setupDir != nil {
				installMarkerFile = tc.setupDir(t, tmpDir)
			}

			src := NewFileDescriptorSource(filepath.Join(tmpDir, installMarkerFile))

			installDescriptor, err := src.ModifyInstallDesc(tc.arg)
			tc.wantErr(t, err)
			assert.Equal(t, tc.expected, installDescriptor)

			if tc.postOpAssertions != nil {
				tc.postOpAssertions(t, tmpDir, installMarkerFile, installDescriptor)
			}
		})
	}
}

func TestFileDescriptorSource_RemoveAgentInstallDesc(t *testing.T) {
	testcases := []struct {
		name             string
		setupDir         func(t *testing.T, tmpDir string) string
		arg              string
		expected         *v1.InstallDescriptor
		wantErr          assert.ErrorAssertionFunc
		postOpAssertions func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor)
	}{
		{
			name:     "no existing file, removing an agent install descriptor returns error",
			arg:      "data/elastic-agent-1.2.3-abcdef",
			expected: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, os.ErrNotExist)
			},
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				assert.NoFileExists(t, filepath.Join(tmpDir, installMarker), "install descriptor should not exist at %s", installMarker)
			},
		},
		{
			name: "empty file, removing an agent install descriptor returns error",
			setupDir: func(t *testing.T, tmpDir string) string {
				markerFileName := "emptydescriptor.yaml"
				err := os.WriteFile(filepath.Join(tmpDir, markerFileName), nil, 0o644)
				require.NoError(t, err, "error creating output file %s", markerFileName)
				return markerFileName
			},
			arg:      "data/elastic-agent-1.2.3-abcdef",
			expected: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, io.EOF)
			},
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				assert.FileExists(t, filepath.Join(tmpDir, installMarker), "install descriptor should not exist at %s", installMarker)
				fileContent, err := os.ReadFile(filepath.Join(tmpDir, installMarker))
				assert.NoError(t, err, "error reading file %s", installMarker)
				assert.Empty(t, fileContent, "install descriptor content should be empty")
			},
		},
		{
			name: "empty descriptor (not file), removing an agent install descriptor should not return error",
			setupDir: func(t *testing.T, tmpDir string) string {
				installDescriptor := v1.NewInstallDescriptor()
				buf := new(bytes.Buffer)
				err := v1.WriteInstallDescriptor(buf, installDescriptor)
				require.NoError(t, err, "error writing install descriptor during setup")

				markerFileName := "zerodescriptor.yaml"
				err = os.WriteFile(filepath.Join(tmpDir, markerFileName), buf.Bytes(), 0o644)
				require.NoError(t, err, "error creating output file %s", markerFileName)
				return markerFileName
			},
			arg:      "data/elastic-agent-1.2.3-abcdef",
			expected: createInstallDescriptor(nil),
			wantErr:  assert.NoError,
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				checkInstallDescriptorMatches(t, filepath.Join(tmpDir, installMarker), actual)
			},
		},
		{
			name: " valid descriptor with multiple installs, removing a descriptor will delete the entries matching the versionedHome",
			setupDir: func(t *testing.T, tmpDir string) string {
				markerFileName := "descriptor.yaml"
				installDescriptor := createInstallDescriptor([]v1.AgentInstallDesc{
					{
						Version:       "4.5.6",
						Hash:          "ghijkl",
						VersionedHome: "date/elastic-agent-4.5.6-ghijkl",
						Flavor:        "basic",
						Active:        false,
					},
					{
						Version:       "1.2.3",
						Hash:          "abcdef",
						VersionedHome: "date/elastic-agent-1.2.3-abcdef",
						Flavor:        "basic",
						Active:        true,
					},
					{
						Version:       "0.0.0",
						Hash:          "oooooo",
						VersionedHome: "date/elastic-agent-0.0.0-oooooo",
						Flavor:        "oooo",
						Active:        false,
					},
					{
						Version:       "1.2.3 x2",
						Hash:          "abcdef",
						VersionedHome: "date/elastic-agent-1.2.3-abcdef",
						Flavor:        "basic",
						Active:        false,
					},
				})

				buf := new(bytes.Buffer)
				err := v1.WriteInstallDescriptor(buf, installDescriptor)
				require.NoError(t, err, "error writing install descriptor during setup")

				err = os.WriteFile(filepath.Join(tmpDir, markerFileName), buf.Bytes(), 0o644)
				require.NoError(t, err, "error creating output file %s", markerFileName)

				return markerFileName
			},
			arg: "date/elastic-agent-1.2.3-abcdef",
			expected: createInstallDescriptor([]v1.AgentInstallDesc{
				{
					Version:       "4.5.6",
					Hash:          "ghijkl",
					VersionedHome: "date/elastic-agent-4.5.6-ghijkl",
					Flavor:        "basic",
					Active:        false,
				},
				{
					Version:       "0.0.0",
					Hash:          "oooooo",
					VersionedHome: "date/elastic-agent-0.0.0-oooooo",
					Flavor:        "oooo",
					Active:        false,
				},
			}),
			wantErr: assert.NoError,
			postOpAssertions: func(t *testing.T, tmpDir string, installMarker string, actual *v1.InstallDescriptor) {
				checkInstallDescriptorMatches(t, filepath.Join(tmpDir, installMarker), actual)
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			installMarkerFile := paths.MarkerFileName
			if tc.setupDir != nil {
				installMarkerFile = tc.setupDir(t, tmpDir)
			}

			src := NewFileDescriptorSource(filepath.Join(tmpDir, installMarkerFile))

			installDescriptor, err := src.RemoveAgentInstallDesc(tc.arg)
			tc.wantErr(t, err)
			assert.Equal(t, tc.expected, installDescriptor)

			if tc.postOpAssertions != nil {
				tc.postOpAssertions(t, tmpDir, installMarkerFile, installDescriptor)
			}
		})
	}
}

func createInstallDescriptor(agentInstalls []v1.AgentInstallDesc) *v1.InstallDescriptor {
	descriptor := v1.NewInstallDescriptor()
	descriptor.AgentInstalls = agentInstalls
	return descriptor
}

func checkInstallDescriptorMatches(t *testing.T, markerFile string, descriptor *v1.InstallDescriptor) {
	require.FileExists(t, markerFile, "install marker file should exist")
	buf := new(bytes.Buffer)
	err := v1.WriteInstallDescriptor(buf, descriptor)
	require.NoError(t, err, "error marshaling install descriptor")
	fileRawData, err := os.ReadFile(markerFile)
	require.NoError(t, err, "error marshaling install descriptor")

	assert.YAMLEq(t, buf.String(), string(fileRawData), "install marker file should match marshalled install descriptor")
}
