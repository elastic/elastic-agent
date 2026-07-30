// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	goerrors "errors"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

const ackMarkerFilename = ".ack-marker"

// AckMarker records that the upgrade action has been successfully acked to Fleet.
// Written exclusively by the agent; never written by the watcher.
type AckMarker struct {
	// ActionID is the Fleet action that was acked.
	ActionID string `yaml:"action_id"`
	// AckedAt is when the ack was confirmed by Fleet Server.
	AckedAt time.Time `yaml:"acked_at"`
}

// WriteAckMarker writes the ack marker to disk, overwriting any previous record.
func WriteAckMarker(dataDirPath string, am *AckMarker) error {
	amBytes, err := yaml.Marshal(am)
	if err != nil {
		return errors.New(err, errors.TypeConfig, "failed to marshal ack marker")
	}

	amPath := ackMarkerFilePath(dataDirPath)
	if err := writeMarkerFile(amPath, amBytes, true); err != nil {
		return goerrors.Join(err, errors.New(errors.TypeFilesystem, "failed to write ack marker file", errors.M(errors.MetaKeyPath, amPath)))
	}

	return nil
}

// LoadAckMarker loads the ack marker, or returns nil if none exists.
func LoadAckMarker(dataDirPath string) (*AckMarker, error) {
	amBytes, err := readMarkerFile(ackMarkerFilePath(dataDirPath))
	if err != nil {
		return nil, err
	}
	if amBytes == nil {
		return nil, nil
	}

	am := &AckMarker{}
	if err := yaml.Unmarshal(amBytes, am); err != nil {
		return nil, err
	}

	return am, nil
}

func ackMarkerFilePath(dataDirPath string) string {
	return filepath.Join(dataDirPath, ackMarkerFilename)
}
