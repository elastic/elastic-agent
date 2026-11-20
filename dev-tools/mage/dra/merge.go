// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package dra

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"
)

// DependencyBuild is the DRA build of one dependency that a merged manifest was
// assembled from.
type DependencyBuild struct {
	Project     string `json:"project"`
	Version     string `json:"version"`
	BuildID     string `json:"build_id"`
	ManifestURL string `json:"manifest_url"`
}

// MergedManifest is the manifest the poller publishes and hands to the
// elastic-agent-package build through MANIFEST_URL.
//
// Its Projects map is the union of the Projects maps of every dependency's own
// DRA manifest, copied verbatim. The packaging code never follows
// external_artifacts_manifest_url; it looks packages up inline under
// projects[<projectName>], so they have to be inlined here.
type MergedManifest struct {
	Version  string `json:"version"`
	Branch   string `json:"branch"`
	Workflow string `json:"workflow"`
	// BuildID identifies the *input set* rather than a build of its own: it is
	// derived from the dependency build IDs, so merging the same dependency
	// builds twice yields the same BuildID. The poller relies on that to tell
	// whether it has already triggered a build for these inputs.
	BuildID string `json:"build_id"`
	// DependencyBuilds records what the manifest was assembled from. It is an
	// addition to the release-manager manifest schema; consumers that do not
	// know about it ignore it.
	DependencyBuilds []DependencyBuild `json:"dependency_builds"`
	// Projects holds raw JSON so that merging preserves every field a
	// dependency publishes, including ones this repository does not model.
	Projects map[string]json.RawMessage `json:"projects"`
}

// AgentCoreProject is the DRA project built from this repository. Its version
// is the one the package takes when dependencies disagree.
//
// Duplicated from devtools.AgentCoreProjectName rather than imported, to keep
// this package free of the dev-tools/mage dependency graph.
const AgentCoreProject = "elastic-agent-core"

// ResolveDependencies looks up the current DRA build of every project under the
// given pointer key.
//
// A project with no published build is skipped rather than treated as an error:
// on a freshly opened release branch some products have not built yet, and
// blocking elastic-agent-package on all of them would mean never building.
// Skipped projects are returned in the second value so callers can report them.
func ResolveDependencies(ctx context.Context, client *ArtifactsClient, key LatestPointerKey, projects []string) (resolved []DependencyBuild, missing []string, err error) {
	for _, project := range projects {
		latest, err := client.LatestBuild(ctx, project, key)
		if errors.Is(err, ErrNoLatestBuild) {
			missing = append(missing, project)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		resolved = append(resolved, DependencyBuild{
			Project:     project,
			Version:     latest.Version,
			BuildID:     latest.BuildID,
			ManifestURL: latest.ManifestURL,
		})
	}

	if len(resolved) == 0 {
		return nil, missing, fmt.Errorf("no dependency has a published %s build (checked %s)",
			key, strings.Join(projects, ", "))
	}
	return resolved, missing, nil
}

// StackVersion returns the version the package is built at, taken from the
// resolved dependency builds, together with any dependencies that disagree.
//
// They normally all report the same version. They diverge for a while after a
// version bump, when some products have moved to the next version and others
// have not. elastic-agent-core wins that tie: it is built from this repository,
// so it is the version the package is actually being produced at.
func StackVersion(deps []DependencyBuild) (version string, disagreeing []string, err error) {
	if len(deps) == 0 {
		return "", nil, fmt.Errorf("no resolved dependencies to take a version from")
	}

	version = deps[0].Version
	for _, dep := range deps {
		if dep.Project == AgentCoreProject {
			version = dep.Version
			break
		}
	}
	if version == "" {
		return "", nil, fmt.Errorf("dependency %s reported no version", deps[0].Project)
	}

	for _, dep := range deps {
		if dep.Version != version {
			disagreeing = append(disagreeing, fmt.Sprintf("%s=%s", dep.Project, dep.Version))
		}
	}
	return version, disagreeing, nil
}

// DependencySetID returns a deterministic identifier for a set of dependency
// builds, in the "<version>-<digest>" shape DRA build IDs use.
//
// Two calls with the same dependency builds return the same ID regardless of
// ordering, and any change — a dependency moving, being added or dropped —
// changes it. That makes it usable both as the merged manifest's build ID and
// as the key the poller checks to see whether these inputs were already built.
func DependencySetID(qualifiedVersion string, deps []DependencyBuild) string {
	lines := make([]string, 0, len(deps))
	for _, dep := range deps {
		lines = append(lines, dep.Project+"="+dep.BuildID)
	}
	sort.Strings(lines)

	digest := sha256.Sum256([]byte(qualifiedVersion + "\n" + strings.Join(lines, "\n")))
	return fmt.Sprintf("%s-%s", qualifiedVersion, hex.EncodeToString(digest[:])[:12])
}

// BuildMergedManifest downloads each resolved dependency's manifest and merges
// their projects into a single manifest.
func BuildMergedManifest(ctx context.Context, client *ArtifactsClient, workflow Workflow, branch, qualifiedVersion string, deps []DependencyBuild) (*MergedManifest, error) {
	merged := &MergedManifest{
		Version:          qualifiedVersion,
		Branch:           branch,
		Workflow:         string(workflow),
		BuildID:          DependencySetID(qualifiedVersion, deps),
		DependencyBuilds: slices.Clone(deps),
		Projects:         map[string]json.RawMessage{},
	}

	// Record which dependency contributed each project so a collision names
	// both sides.
	contributedBy := map[string]string{}

	for _, dep := range deps {
		raw, err := client.RawManifest(ctx, dep.ManifestURL)
		if err != nil {
			return nil, fmt.Errorf("merging %s: %w", dep.Project, err)
		}

		var depManifest struct {
			Projects map[string]json.RawMessage `json:"projects"`
		}
		if err := json.Unmarshal(raw, &depManifest); err != nil {
			return nil, fmt.Errorf("decoding manifest of %s from %s: %w", dep.Project, dep.ManifestURL, err)
		}
		if len(depManifest.Projects) == 0 {
			return nil, fmt.Errorf("manifest of %s at %s contains no projects", dep.Project, dep.ManifestURL)
		}

		// A dependency's manifest may describe more projects than the one we
		// asked for (the beats manifest describes filebeat, metricbeat, ...).
		// Inline all of them: packages.yml refers to projects by name and a
		// future component may use one of the extras.
		for name, project := range depManifest.Projects {
			if previous, clash := contributedBy[name]; clash && previous != dep.Project {
				return nil, fmt.Errorf("project %q is published by both %s and %s; cannot merge their manifests unambiguously",
					name, previous, dep.Project)
			}
			contributedBy[name] = dep.Project
			merged.Projects[name] = project
		}
	}

	return merged, nil
}

// Validate checks that the merged manifest can actually satisfy the components
// declared in packages.yml, so that a missing project is reported by the poller
// instead of failing the packaging step half an hour later.
func (m *MergedManifest) Validate(requiredProjects []string) error {
	var missing []string
	for _, project := range requiredProjects {
		if _, ok := m.Projects[project]; !ok {
			missing = append(missing, project)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("merged manifest is missing projects required by packages.yml: %s", strings.Join(missing, ", "))
	}
	return nil
}

// MarshalIndent renders the merged manifest as the JSON document published to GCS.
func (m *MergedManifest) MarshalIndent() ([]byte, error) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding merged manifest: %w", err)
	}
	return append(data, '\n'), nil
}

// LogSummary prints one line per dependency build.
func (m *MergedManifest) LogSummary(logger *log.Logger) {
	logger.Printf("merged manifest %s (%d projects) from:", m.BuildID, len(m.Projects))
	for _, dep := range m.DependencyBuilds {
		logger.Printf("  %-20s %s", dep.Project, dep.BuildID)
	}
}
