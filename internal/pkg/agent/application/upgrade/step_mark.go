// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const markerFilename = ".update-marker"

// UpdateMarker is a marker holding necessary information about ongoing upgrade.
type UpdateMarker struct {
	// Hash agent is updated to
	Hash string `json:"hash" yaml:"hash"`
	//UpdatedOn marks a date when update happened
	UpdatedOn time.Time `json:"updated_on" yaml:"updated_on"`

	// PrevVersion is a version agent is updated from
	PrevVersion string `json:"prev_version" yaml:"prev_version"`
	// PrevHash is a hash agent is updated from
	PrevHash string `json:"prev_hash" yaml:"prev_hash"`

	// Acked is a flag marking whether or not action was acked
	Acked  bool                    `json:"acked" yaml:"acked"`
	Action *fleetapi.ActionUpgrade `json:"action" yaml:"action"`

	Details *details.Details `json:"details,omitempty" yaml:"details,omitempty"`
}

// MarkerActionUpgrade adapter struct compatible with pre 8.3 version of the marker file format
type MarkerActionUpgrade struct {
	ActionID   string `yaml:"id"`
	ActionType string `yaml:"type"`
	Version    string `yaml:"version"`
	SourceURI  string `yaml:"source_uri,omitempty"`
}

func convertToMarkerAction(a *fleetapi.ActionUpgrade) *MarkerActionUpgrade {
	if a == nil {
		return nil
	}
	return &MarkerActionUpgrade{
		ActionID:   a.ActionID,
		ActionType: a.ActionType,
		Version:    a.Version,
		SourceURI:  a.SourceURI,
	}
}

func convertToActionUpgrade(a *MarkerActionUpgrade) *fleetapi.ActionUpgrade {
	if a == nil {
		return nil
	}
	return &fleetapi.ActionUpgrade{
		ActionID:   a.ActionID,
		ActionType: a.ActionType,
		Version:    a.Version,
		SourceURI:  a.SourceURI,
	}
}

type updateMarkerSerializer struct {
	Hash        string               `yaml:"hash"`
	UpdatedOn   time.Time            `yaml:"updated_on"`
	PrevVersion string               `yaml:"prev_version"`
	PrevHash    string               `yaml:"prev_hash"`
	Acked       bool                 `yaml:"acked"`
	Action      *MarkerActionUpgrade `yaml:"action"`
	Details     *details.Details     `yaml:"details"`
}

func newMarkerSerializer(m *UpdateMarker) *updateMarkerSerializer {
	return &updateMarkerSerializer{
		Hash:        m.Hash,
		UpdatedOn:   m.UpdatedOn,
		PrevVersion: m.PrevVersion,
		PrevHash:    m.PrevHash,
		Acked:       m.Acked,
		Action:      convertToMarkerAction(m.Action),
		Details:     m.Details,
	}
}

// markUpgrade marks update happened so we can handle grace period
func (u *Upgrader) markUpgrade(_ context.Context, log *logger.Logger, hash string, action *fleetapi.ActionUpgrade, upgradeDetails *details.Details) error {
	prevVersion := release.Version()
	prevHash := release.Commit()
	if len(prevHash) > hashLen {
		prevHash = prevHash[:hashLen]
	}

	marker := &UpdateMarker{
		Hash:        hash,
		UpdatedOn:   time.Now(),
		PrevVersion: prevVersion,
		PrevHash:    prevHash,
		Action:      action,
		Details:     upgradeDetails,
	}

	markerBytes, err := yaml.Marshal(newMarkerSerializer(marker))
	if err != nil {
		return errors.New(err, errors.TypeConfig, "failed to parse marker file")
	}

	markerPath := markerFilePath()
	log.Infow("Writing upgrade marker file", "file.path", markerPath, "hash", marker.Hash, "prev_hash", prevHash)
	if err := ioutil.WriteFile(markerPath, markerBytes, 0600); err != nil {
		return errors.New(err, errors.TypeFilesystem, "failed to create update marker file", errors.M(errors.MetaKeyPath, markerPath))
	}

	if err := UpdateActiveCommit(log, hash); err != nil {
		return err
	}

	return nil
}

// UpdateActiveCommit updates active.commit file to point to active version.
func UpdateActiveCommit(log *logger.Logger, hash string) error {
	activeCommitPath := filepath.Join(paths.Top(), agentCommitFile)
	log.Infow("Updating active commit", "file.path", activeCommitPath, "hash", hash)
	if err := ioutil.WriteFile(activeCommitPath, []byte(hash), 0600); err != nil {
		return errors.New(err, errors.TypeFilesystem, "failed to update active commit", errors.M(errors.MetaKeyPath, activeCommitPath))
	}

	return nil
}

// CleanMarker removes a marker from disk.
func CleanMarker(log *logger.Logger) error {
	markerFile := markerFilePath()
	log.Infow("Removing marker file", "file.path", markerFile)
	if err := os.Remove(markerFile); !os.IsNotExist(err) {
		return err
	}

	return nil
}

// LoadMarker loads the update marker. If the file does not exist it returns nil
// and no error.
func LoadMarker() (*UpdateMarker, error) {
	markerFile := markerFilePath()
	markerBytes, err := ioutil.ReadFile(markerFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	marker := &updateMarkerSerializer{}
	if err := yaml.Unmarshal(markerBytes, &marker); err != nil {
		return nil, err
	}

	return &UpdateMarker{
		Hash:        marker.Hash,
		UpdatedOn:   marker.UpdatedOn,
		PrevVersion: marker.PrevVersion,
		PrevHash:    marker.PrevHash,
		Acked:       marker.Acked,
		Action:      convertToActionUpgrade(marker.Action),
		Details:     marker.Details,
	}, nil
}

func saveMarker(marker *UpdateMarker) error {
	makerSerializer := &updateMarkerSerializer{
		Hash:        marker.Hash,
		UpdatedOn:   marker.UpdatedOn,
		PrevVersion: marker.PrevVersion,
		PrevHash:    marker.PrevHash,
		Acked:       marker.Acked,
		Action:      convertToMarkerAction(marker.Action),
		Details:     marker.Details,
	}
	markerBytes, err := yaml.Marshal(makerSerializer)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(markerFilePath(), markerBytes, 0600)
}

func markerFilePath() string {
	return filepath.Join(paths.Data(), markerFilename)
}
