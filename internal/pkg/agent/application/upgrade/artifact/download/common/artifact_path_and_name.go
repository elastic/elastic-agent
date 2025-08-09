package common

import (
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/pkg/version"
)

type ArtifactPathAndName struct {
	ArtifactName string
	HashName     string
	ArtifactPath string
	HashPath     string
}

type GetArtifactPathAndNameFunc func(a artifact.Artifact, version version.ParsedSemVer, remoteArtifact, operatingSystem, arch, targetDir string) (ArtifactPathAndName, error)

func GetArtifactPathAndName(a artifact.Artifact, version version.ParsedSemVer, remoteArtifact, operatingSystem, arch, targetDir string) (ArtifactPathAndName, error) {
	filename, err := artifact.GetArtifactName(a, version, operatingSystem, arch)
	if err != nil {
		return ArtifactPathAndName{}, fmt.Errorf("generating package name failed: %w", err)
	}

	fullPath, err := artifact.GetArtifactPath(a, version, operatingSystem, arch, targetDir)
	if err != nil {
		return ArtifactPathAndName{}, fmt.Errorf("generating package path failed: %w", err)
	}

	return ArtifactPathAndName{
		ArtifactName: filename,
		HashName:     filename + ".sha512",
		ArtifactPath: fullPath,
		HashPath:     fullPath + ".sha512",
	}, nil
}
