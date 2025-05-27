// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/version"
)

const markerFilename = ".update-marker"

// UpgradeOutcome can have 2 values, UPGRADE by default and ROLLBACK when rollback was initiated manually
type UpgradeOutcome int

const (
	OUTCOME_UPGRADE UpgradeOutcome = iota
	OUTCOME_ROLLBACK
)

// UpdateMarker is a marker holding necessary information about ongoing upgrade.
type UpdateMarker struct {
	// Version represents the version the agent is upgraded to
	Version string `json:"version" yaml:"version"`
	// Hash agent is updated to
	Hash string `json:"hash" yaml:"hash"`
	// VersionedHome represents the path where the new agent is located relative to top path
	VersionedHome string `json:"versioned_home" yaml:"versioned_home"`

	//UpdatedOn marks a date when update happened
	UpdatedOn time.Time `json:"updated_on" yaml:"updated_on"`

	// PrevVersion is a version agent is updated from
	PrevVersion string `json:"prev_version" yaml:"prev_version"`
	// PrevHash is a hash agent is updated from
	PrevHash string `json:"prev_hash" yaml:"prev_hash"`
	// PrevVersionedHome represents the path where the old agent is located relative to top path
	PrevVersionedHome string `json:"prev_versioned_home" yaml:"prev_versioned_home"`

	// Acked is a flag marking whether or not action was acked
	Acked  bool                    `json:"acked" yaml:"acked"`
	Action *fleetapi.ActionUpgrade `json:"action" yaml:"action"`

	Details *details.Details `json:"details,omitempty" yaml:"details,omitempty"`

	DesiredOutcome UpgradeOutcome `json:"desired_outcome" yaml:"desired_outcome"`
}

// GetActionID returns the Fleet Action ID associated with the
// upgrade action, if it's recorded in the UpdateMarker.
func (um UpdateMarker) GetActionID() string {
	if um.Action != nil {
		return um.Action.ActionID
	}
	return ""
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
		Version:    a.Data.Version,
		SourceURI:  a.Data.SourceURI,
	}
}

func convertToActionUpgrade(a *MarkerActionUpgrade) *fleetapi.ActionUpgrade {
	if a == nil {
		return nil
	}
	return &fleetapi.ActionUpgrade{
		ActionID:   a.ActionID,
		ActionType: a.ActionType,
		Data: fleetapi.ActionUpgradeData{
			Version:   a.Version,
			SourceURI: a.SourceURI,
		},
	}
}

type updateMarkerSerializer struct {
	Version           string               `yaml:"version"`
	Hash              string               `yaml:"hash"`
	VersionedHome     string               `yaml:"versioned_home"`
	UpdatedOn         time.Time            `yaml:"updated_on"`
	PrevVersion       string               `yaml:"prev_version"`
	PrevHash          string               `yaml:"prev_hash"`
	PrevVersionedHome string               `yaml:"prev_versioned_home"`
	Acked             bool                 `yaml:"acked"`
	Action            *MarkerActionUpgrade `yaml:"action"`
	Details           *details.Details     `yaml:"details"`
	DesiredOutcome    UpgradeOutcome       `yaml:"desired_outcome"`
}

func newMarkerSerializer(m *UpdateMarker) *updateMarkerSerializer {
	return &updateMarkerSerializer{
		Version:           m.Version,
		Hash:              m.Hash,
		VersionedHome:     m.VersionedHome,
		UpdatedOn:         m.UpdatedOn,
		PrevVersion:       m.PrevVersion,
		PrevHash:          m.PrevHash,
		PrevVersionedHome: m.PrevVersionedHome,
		Acked:             m.Acked,
		Action:            convertToMarkerAction(m.Action),
		Details:           m.Details,
		DesiredOutcome:    m.DesiredOutcome,
	}
}

func (o UpgradeOutcome) String() string {
	switch o {
	case OUTCOME_UPGRADE:
		return "UPGRADE"
	case OUTCOME_ROLLBACK:
		return "ROLLBACK"
	default:
		return ""
	}
}

// JSON marshaling
func (o UpgradeOutcome) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.String())
}

func (o *UpgradeOutcome) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "UPGRADE":
		*o = OUTCOME_UPGRADE
	case "ROLLBACK":
		*o = OUTCOME_ROLLBACK
	case "":
		*o = OUTCOME_UPGRADE
	default:
		return fmt.Errorf("invalid Operation: %s", s)
	}
	return nil
}

// YAML marshaling
func (o UpgradeOutcome) MarshalYAML() (interface{}, error) {
	return o.String(), nil
}

func (o *UpgradeOutcome) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	switch s {
	case "UPGRADE":
		*o = OUTCOME_UPGRADE
	case "ROLLBACK":
		*o = OUTCOME_ROLLBACK
	case "":
		*o = OUTCOME_UPGRADE
	default:
		return fmt.Errorf("invalid UpgradeOutcome: %s", s)
	}
	return nil
}

type agentInstall struct {
	parsedVersion *version.ParsedSemVer
	version       string
	hash          string
	versionedHome string
}

// markUpgrade marks update happened so we can handle grace period
func markUpgrade(log *logger.Logger, dataDirPath string, agent, previousAgent agentInstall, action *fleetapi.ActionUpgrade, upgradeDetails *details.Details, desiredOutcome UpgradeOutcome) error {

	if len(previousAgent.hash) > hashLen {
		previousAgent.hash = previousAgent.hash[:hashLen]
	}

	marker := &UpdateMarker{
		Version:           agent.version,
		Hash:              agent.hash,
		VersionedHome:     agent.versionedHome,
		UpdatedOn:         time.Now(),
		PrevVersion:       previousAgent.version,
		PrevHash:          previousAgent.hash,
		PrevVersionedHome: previousAgent.versionedHome,
		Action:            action,
		Details:           upgradeDetails,
		DesiredOutcome:    desiredOutcome,
	}

	markerBytes, err := yaml.Marshal(newMarkerSerializer(marker))
	if err != nil {
		return errors.New(err, errors.TypeConfig, "failed to parse marker file")
	}

	markerPath := markerFilePath(dataDirPath)
	log.Infow("Writing upgrade marker file", "file.path", markerPath, "hash", marker.Hash, "prev_hash", marker.PrevHash)
	markerFileLock, err := lockMarkerFile(markerPath)
	if err != nil {
		return fmt.Errorf("failed locking marker file: %w", err)
	}

	defer func(markerFileLock *flock.Flock) {
		err := markerFileLock.Unlock()
		if err != nil {
			log.Warnw("Failed to unlock marker file", "file.path", markerPath, "err", err)
		}
	}(markerFileLock)

	if err := os.WriteFile(markerPath, markerBytes, 0600); err != nil {
		return errors.New(err, errors.TypeFilesystem, "failed to create update marker file", errors.M(errors.MetaKeyPath, markerPath))
	}

	if err := UpdateActiveCommit(log, paths.Top(), agent.hash); err != nil {
		return err
	}

	return nil
}

// UpdateActiveCommit updates active.commit file to point to active version.
func UpdateActiveCommit(log *logger.Logger, topDirPath, hash string) error {
	activeCommitPath := filepath.Join(topDirPath, agentCommitFile)
	log.Infow("Updating active commit", "file.path", activeCommitPath, "hash", hash)
	if err := os.WriteFile(activeCommitPath, []byte(hash), 0600); err != nil {
		return errors.New(err, errors.TypeFilesystem, "failed to update active commit", errors.M(errors.MetaKeyPath, activeCommitPath))
	}

	return nil
}

// CleanMarker removes a marker from disk.
func CleanMarker(log *logger.Logger, dataDirPath string) error {
	markerFile := markerFilePath(dataDirPath)
	log.Infow("Removing marker file", "file.path", markerFile)
	if err := os.Remove(markerFile); !os.IsNotExist(err) {
		return err
	}

	return nil
}

// LoadMarker loads the update marker. If the file does not exist it returns nil
// and no error.
func LoadMarker(dataDirPath string) (*UpdateMarker, error) {
	return loadMarker(markerFilePath(dataDirPath))
}

func loadMarker(markerFile string) (*UpdateMarker, error) {
	markerBytes, err := readMarkerFile(markerFile)
	if err != nil {
		return nil, err
	}
	if markerBytes == nil {
		// marker doesn't exist
		return nil, nil
	}

	marker := &updateMarkerSerializer{}
	if err := yaml.Unmarshal(markerBytes, &marker); err != nil {
		return nil, err
	}

	return &UpdateMarker{
		Version:           marker.Version,
		Hash:              marker.Hash,
		VersionedHome:     marker.VersionedHome,
		UpdatedOn:         marker.UpdatedOn,
		PrevVersion:       marker.PrevVersion,
		PrevHash:          marker.PrevHash,
		PrevVersionedHome: marker.PrevVersionedHome,
		Acked:             marker.Acked,
		Action:            convertToActionUpgrade(marker.Action),
		Details:           marker.Details,
		DesiredOutcome:    marker.DesiredOutcome,
	}, nil
}

// SaveMarker serializes and persists the given upgrade marker to disk.
// For critical upgrade transitions, pass shouldFsync as true so the marker
// file is immediately flushed to persistent storage.
func SaveMarker(marker *UpdateMarker, shouldFsync bool) error {
	return saveMarkerToPath(marker, markerFilePath(paths.Data()), shouldFsync)
}

func saveMarkerToPath(marker *UpdateMarker, markerFile string, shouldFsync bool) error {
	makerSerializer := &updateMarkerSerializer{
		Version:           marker.Version,
		Hash:              marker.Hash,
		VersionedHome:     marker.VersionedHome,
		UpdatedOn:         marker.UpdatedOn,
		PrevVersion:       marker.PrevVersion,
		PrevHash:          marker.PrevHash,
		PrevVersionedHome: marker.PrevVersionedHome,
		Acked:             marker.Acked,
		Action:            convertToMarkerAction(marker.Action),
		Details:           marker.Details,
		DesiredOutcome:    marker.DesiredOutcome,
	}
	markerBytes, err := yaml.Marshal(makerSerializer)
	if err != nil {
		return err
	}

	return writeMarkerFile(markerFile, markerBytes, shouldFsync)
}

func markerFilePath(dataDirPath string) string {
	return filepath.Join(dataDirPath, markerFilename)
}

func lockMarkerFile(markerFileName string) (*flock.Flock, error) {
	fLock := flock.New(markerFileName + ".lock")
	_, err := fLock.TryLock()
	if err != nil {
		return nil, err
	}

	return fLock, nil
}
