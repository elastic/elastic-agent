// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	goerrors "errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/version"
)

const markerFilename = ".update-marker"

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

	RollbacksAvailable map[string]ttl.TTLMarker `json:"rollbacks_available,omitempty" yaml:"rollbacks_available,omitempty"`
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
	Version            string                   `yaml:"version"`
	Hash               string                   `yaml:"hash"`
	VersionedHome      string                   `yaml:"versioned_home"`
	UpdatedOn          time.Time                `yaml:"updated_on"`
	PrevVersion        string                   `yaml:"prev_version"`
	PrevHash           string                   `yaml:"prev_hash"`
	PrevVersionedHome  string                   `yaml:"prev_versioned_home"`
	Acked              bool                     `yaml:"acked"`
	Action             *MarkerActionUpgrade     `yaml:"action"`
	Details            *details.Details         `yaml:"details"`
	RollbacksAvailable map[string]ttl.TTLMarker `yaml:"rollbacks_available,omitempty"`
}

func newMarkerSerializer(m *UpdateMarker) *updateMarkerSerializer {
	return &updateMarkerSerializer{
		Version:            m.Version,
		Hash:               m.Hash,
		VersionedHome:      m.VersionedHome,
		UpdatedOn:          m.UpdatedOn,
		PrevVersion:        m.PrevVersion,
		PrevHash:           m.PrevHash,
		PrevVersionedHome:  m.PrevVersionedHome,
		Acked:              m.Acked,
		Action:             convertToMarkerAction(m.Action),
		Details:            m.Details,
		RollbacksAvailable: m.RollbacksAvailable,
	}
}

type agentInstall struct {
	parsedVersion *version.ParsedSemVer
	version       string
	hash          string
	versionedHome string
}

type updateActiveCommitFunc func(log *logger.Logger, topDirPath, hash string, writeFile writeFileFunc) error

// writeUpgradeMarkerProvider returns a function that writes the upgrade marker file.
// It does not update active.commit; use it to protect the target directory before unpacking starts.
func writeUpgradeMarkerProvider() writeUpgradeMarkerFunc {
	return func(log *logger.Logger, dataDirPath string, updatedOn time.Time, agent, previousAgent agentInstall, action *fleetapi.ActionUpgrade, upgradeDetails *details.Details, availableRollbacks map[string]ttl.TTLMarker) error {
		if len(previousAgent.hash) > HashLen {
			previousAgent.hash = previousAgent.hash[:HashLen]
		}

		marker := &UpdateMarker{
			Version:            agent.version,
			Hash:               agent.hash,
			VersionedHome:      agent.versionedHome,
			UpdatedOn:          updatedOn,
			PrevVersion:        previousAgent.version,
			PrevHash:           previousAgent.hash,
			PrevVersionedHome:  previousAgent.versionedHome,
			Action:             action,
			Details:            upgradeDetails,
			RollbacksAvailable: availableRollbacks,
		}

		markerBytes, err := yaml.Marshal(newMarkerSerializer(marker))
		if err != nil {
			return errors.New(err, errors.TypeConfig, "failed to parse marker file")
		}

		markerPath := markerFilePath(dataDirPath)
		log.Infow("Writing upgrade marker file", "file.path", markerPath, "hash", marker.Hash, "prev_hash", marker.PrevHash)
		if err := writeMarkerFile(markerPath, markerBytes, true); err != nil {
			return goerrors.Join(err, errors.New(errors.TypeFilesystem, "failed to create update marker file", errors.M(errors.MetaKeyPath, markerPath)))
		}

		return nil
	}
}

// markUpgradeProvider returns a function that writes the upgrade marker file and updates active.commit.
// Use it after the symlink has been flipped to the new binary.
func markUpgradeProvider(updateActiveCommit updateActiveCommitFunc, writeFile writeFileFunc) markUpgradeFunc {
	writeMarker := writeUpgradeMarkerProvider()
	return func(log *logger.Logger, dataDirPath string, updatedOn time.Time, agent, previousAgent agentInstall, action *fleetapi.ActionUpgrade, upgradeDetails *details.Details, availableRollbacks map[string]ttl.TTLMarker) error {
		if err := writeMarker(log, dataDirPath, updatedOn, agent, previousAgent, action, upgradeDetails, availableRollbacks); err != nil {
			return err
		}
		return updateActiveCommit(log, paths.Top(), agent.hash, writeFile)
	}
}

// UpdateActiveCommit updates active.commit file to point to active version.
func UpdateActiveCommit(log *logger.Logger, topDirPath, hash string, writeFile writeFileFunc) error {
	activeCommitPath := filepath.Join(topDirPath, agentCommitFile)
	log.Infow("Updating active commit", "file.path", activeCommitPath, "hash", hash)
	if err := writeFile(activeCommitPath, []byte(hash), 0600); err != nil {
		return goerrors.Join(err, errors.New(errors.TypeFilesystem, "failed to update active commit", errors.M(errors.MetaKeyPath, activeCommitPath)))
	}

	return nil
}

// MarkUpgradeFailed records an upgrade failure both in the in-memory
// upgrade-details (det.Fail(cause)) and, if a marker is on disk, by saving
// the marker with state=Failed so the failure is surfaced to Fleet via the
// next upgrade-details ack.
//
// Designed as the single entry point for marking an upgrade as failed across
// every error path that can run after the upgrade flow has begun, regardless
// of whether the marker file was ever written. det is always mutated; the
// marker step is best-effort and a no-op when no marker exists (e.g.
// markUpgrade failed before writing it, or the failure happened before the
// marker was created), so callers can invoke it uniformly without first
// checking marker presence.
//
// The on-disk part is what prevents the next agent run from starting a
// watcher against an upgrade that has already been undone
// (https://github.com/elastic/elastic-agent/issues/13505).
func MarkUpgradeFailed(dataDirPath string, det *details.Details, cause error) error {
	det.Fail(cause)
	marker, err := LoadMarker(dataDirPath)
	if err != nil {
		return errors.New(err, errors.TypeFilesystem, "loading marker after upgrade failure")
	}
	if marker == nil {
		return nil
	}
	marker.Details = det
	if err := SaveMarker(dataDirPath, marker, true); err != nil {
		return errors.New(err, errors.TypeFilesystem, "saving failed-state marker")
	}
	return nil
}

// CleanMarker removes a marker from disk.
func CleanMarker(log *logger.Logger, dataDirPath string) error {
	markerFile := markerFilePath(dataDirPath)
	log.Infow("Removing marker file", "file.path", markerFile)
	// The leading err != nil guard is load-bearing — errors.Is(nil, fs.ErrNotExist)
	// returns false, so dropping the guard would cause the success case
	// (err == nil) to also enter the return branch. Currently harmless
	// because there's no work after this block, but brittle to future
	// additions; keep the guard.
	if err := os.Remove(markerFile); err != nil && !goerrors.Is(err, fs.ErrNotExist) {
		return err
	}

	return nil
}

// LoadMarker loads the update marker. If the file does not exist it returns nil
// and no error.
func LoadMarker(dataDirPath string) (*UpdateMarker, error) {
	return loadMarker(markerFilePath(dataDirPath))
}

// TryLoadMarker loads the upgrade marker. If the file does not exist it
// returns nil and no error. Unlike LoadMarker, if the file exists but cannot be
// parsed (e.g. corrupted by a crash during an upgrade write), it renames the
// corrupt file and returns nil so startup can proceed without upgrade state.
func TryLoadMarker(log *logger.Logger, dataDirPath string) (*UpdateMarker, error) {
	markerFile := markerFilePath(dataDirPath)
	marker, err := loadMarker(markerFile)
	if err == nil {
		return marker, nil
	}

	// The file exists but could not be parsed. Move it aside so the agent can
	// start without upgrade state rather than aborting startup entirely.
	corruptPath := markerFile + ".corrupt"
	if renameErr := os.Rename(markerFile, corruptPath); renameErr != nil {
		log.Warnf("corrupt upgrade marker at %s could not be moved to %s (parse error: %v, rename error: %v); starting without upgrade state",
			markerFile, corruptPath, err, renameErr)
	} else {
		log.Warnf("corrupt upgrade marker moved to %s (parse error: %v); starting without upgrade state",
			corruptPath, err)
	}
	return nil, nil
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
		Version:            marker.Version,
		Hash:               marker.Hash,
		VersionedHome:      marker.VersionedHome,
		UpdatedOn:          marker.UpdatedOn,
		PrevVersion:        marker.PrevVersion,
		PrevHash:           marker.PrevHash,
		PrevVersionedHome:  marker.PrevVersionedHome,
		Acked:              marker.Acked,
		Action:             convertToActionUpgrade(marker.Action),
		Details:            marker.Details,
		RollbacksAvailable: marker.RollbacksAvailable,
	}, nil
}

// SaveMarker serializes and persists the given upgrade marker to disk.
// For critical upgrade transitions, pass shouldFsync as true so the marker
// file is immediately flushed to persistent storage.
func SaveMarker(dataDirPath string, marker *UpdateMarker, shouldFsync bool) error {
	return saveMarkerToPath(marker, markerFilePath(dataDirPath), shouldFsync)
}

func saveMarkerToPath(marker *UpdateMarker, markerFile string, shouldFsync bool) error {
	makerSerializer := &updateMarkerSerializer{
		Version:            marker.Version,
		Hash:               marker.Hash,
		VersionedHome:      marker.VersionedHome,
		UpdatedOn:          marker.UpdatedOn,
		PrevVersion:        marker.PrevVersion,
		PrevHash:           marker.PrevHash,
		PrevVersionedHome:  marker.PrevVersionedHome,
		Acked:              marker.Acked,
		Action:             convertToMarkerAction(marker.Action),
		Details:            marker.Details,
		RollbacksAvailable: marker.RollbacksAvailable,
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

// IsTerminalState returns true if the state in the upgrade marker contains details and the upgrade details state is a
// terminal one: UPG_COMPLETE, UPG_ROLLBACK and UPG_FAILED
// If the upgrade marker or the upgrade marker details are nil the function will return false: as
// no state is specified, having simply a marker without details would mean that some upgrade operation is ongoing
// (probably initiated by an older agent).
func IsTerminalState(marker *UpdateMarker) bool {
	if marker.Details == nil {
		return false
	}

	switch marker.Details.State {
	case details.StateCompleted, details.StateRollback, details.StateFailed:
		return true
	default:
		return false
	}
}
