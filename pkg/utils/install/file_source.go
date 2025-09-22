// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
)

type FileDescriptorSource struct {
	descriptorFile string
}

func NewFileDescriptorSource(descriptorFile string) *FileDescriptorSource {
	return &FileDescriptorSource{descriptorFile: descriptorFile}
}

func (dp *FileDescriptorSource) AddInstallDesc(desc v1.AgentInstallDesc) (*v1.InstallDescriptor, error) {
	installDescriptor, err := readInstallMarkerFile(dp.descriptorFile)
	// not existing or empty files are tolerated, since we would be writing a new descriptor, return any other error
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, io.EOF) {
		return nil, err
	}

	if installDescriptor == nil {
		installDescriptor = v1.NewInstallDescriptor()
	}

	existingInstalls := installDescriptor.AgentInstalls
	installDescriptor.AgentInstalls = make([]v1.AgentInstallDesc, len(existingInstalls)+1)
	installDescriptor.AgentInstalls[0] = desc
	copied := copy(installDescriptor.AgentInstalls[1:], existingInstalls)
	if copied != len(existingInstalls) {
		return nil, fmt.Errorf("error adding new install %v to existing installs %v", desc, existingInstalls)
	}

	err = writeInstallMarkerFile(dp.descriptorFile, installDescriptor)
	if err != nil {
		return nil, fmt.Errorf("writing updated install marker: %w", err)
	}

	return installDescriptor, nil
}

func (dp *FileDescriptorSource) ModifyInstallDesc(modifierFunc func(desc *v1.AgentInstallDesc) error) (*v1.InstallDescriptor, error) {
	installDescriptor, err := readInstallMarkerFile(dp.descriptorFile)
	if err != nil {
		return nil, err
	}

	if installDescriptor == nil {
		return nil, fmt.Errorf("no install descriptor found at %q", dp.descriptorFile)
	}

	for i := range installDescriptor.AgentInstalls {
		err = modifierFunc(&installDescriptor.AgentInstalls[i])
		if err != nil {
			return nil, fmt.Errorf("modifying agent install %s: %w", installDescriptor.AgentInstalls[i].VersionedHome, err)
		}
	}

	err = writeInstallMarkerFile(dp.descriptorFile, installDescriptor)
	if err != nil {
		return nil, fmt.Errorf("writing updated install marker: %w", err)
	}

	return installDescriptor, nil
}

func (dp *FileDescriptorSource) RemoveAgentInstallDesc(versionedHome string) (*v1.InstallDescriptor, error) {
	installDescriptor, err := readInstallMarkerFile(dp.descriptorFile)
	if err != nil {
		return nil, err
	}

	if installDescriptor == nil {
		return nil, fmt.Errorf("no install descriptor found at %q", dp.descriptorFile)
	}

	installDescriptor.AgentInstalls = slices.DeleteFunc(installDescriptor.AgentInstalls, func(installDesc v1.AgentInstallDesc) bool {
		return installDesc.VersionedHome == versionedHome
	})

	err = writeInstallMarkerFile(dp.descriptorFile, installDescriptor)
	if err != nil {
		return nil, fmt.Errorf("writing updated install marker: %w", err)
	}

	return installDescriptor, nil
}

func writeInstallMarkerFile(markerFilePath string, descriptor *v1.InstallDescriptor) error {
	installMarkerFile, err := os.Create(markerFilePath)
	if err != nil {
		return fmt.Errorf("opening install marker file: %w", err)
	}
	defer func(installMarkerFile *os.File) {
		_ = installMarkerFile.Close()
	}(installMarkerFile)
	return v1.WriteInstallDescriptor(installMarkerFile, descriptor)
}

func readInstallMarkerFile(markerFilePath string) (*v1.InstallDescriptor, error) {
	installMarkerFile, err := os.Open(markerFilePath)
	if err != nil {
		return nil, fmt.Errorf("opening install marker file: %w", err)
	}
	defer func(installMarkerFile *os.File) {
		_ = installMarkerFile.Close()
	}(installMarkerFile)
	installDescriptor, err := v1.ParseInstallDescriptor(installMarkerFile)
	if err != nil {
		return nil, fmt.Errorf("parsing install marker file: %w", err)
	}
	return installDescriptor, nil
}
