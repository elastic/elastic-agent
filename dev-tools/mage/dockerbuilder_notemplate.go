// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"

	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/pkg/component"
)

// UseNoTemplateDockerBuild returns true if the DOCKER_NO_TEMPLATE environment
// variable is set to "true" or "1", indicating that the new template-free
// Docker build path should be used.
func UseNoTemplateDockerBuild() bool {
	val := os.Getenv("DOCKER_NO_TEMPLATE")
	return val == "true" || val == "1"
}

// dockerBuilderNoTemplate builds Docker images using build args instead of templates.
type dockerBuilderNoTemplate struct {
	PackageSpec

	imageName       string
	buildDir        string
	beatDir         string
	isBuildxEnabled bool
}

func newDockerBuilderNoTemplate(spec PackageSpec) (*dockerBuilderNoTemplate, error) {
	buildDir := filepath.Join(spec.packageDir, "docker-build")
	beatDir := filepath.Join(buildDir, "beat")

	buildxEnabled := isBuildxEnabled()
	if buildxEnabled {
		fmt.Println("Docker buildx is available, cross-platform builds are possible")
	} else {
		fmt.Println("Docker buildx is not available")
	}

	return &dockerBuilderNoTemplate{
		PackageSpec:     spec,
		imageName:       spec.ImageName(),
		buildDir:        buildDir,
		beatDir:         beatDir,
		isBuildxEnabled: buildxEnabled,
	}, nil
}

func (b *dockerBuilderNoTemplate) Build() error {
	if err := os.RemoveAll(b.buildDir); err != nil {
		return fmt.Errorf("failed to clean existing build directory %s: %w", b.buildDir, err)
	}

	if err := b.copyFiles(); err != nil {
		return fmt.Errorf("error copying files for docker variant %q: %w", b.DockerVariant, err)
	}

	if err := b.prepareBuild(); err != nil {
		return fmt.Errorf("failed to prepare build: %w", err)
	}

	tag, additionalTags, err := b.dockerBuild()
	tries := 3
	for err != nil && tries != 0 {
		fmt.Println(">> Building docker images again (after 10 s)")
		time.Sleep(time.Second * 10)
		tag, additionalTags, err = b.dockerBuild()
		tries--
	}
	if err != nil {
		return fmt.Errorf("failed to build docker: %w", err)
	}

	if err := b.dockerSave(tag); err != nil {
		return fmt.Errorf("failed to save docker as artifact: %w", err)
	}

	for _, tag := range additionalTags {
		if err := b.dockerSave(tag, map[string]interface{}{
			"Name": strings.ReplaceAll(tag, ":", "-"),
		}); err != nil {
			return fmt.Errorf("failed to save docker with tag %s as artifact: %w", tag, err)
		}
	}

	return nil
}

func (b *dockerBuilderNoTemplate) copyFiles() error {
	for _, f := range b.Files {
		source := f.Source
		var checkFn func(string) bool
		target := filepath.Join(b.beatDir, f.Target)

		if f.ExpandSpec {
			specFilename := filepath.Base(source)
			specContent, err := os.ReadFile(source)
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return fmt.Errorf("failed reading spec file for component %q: %w", specFilename, err)
			}

			allowedPaths, err := component.ParseComponentFiles(specContent, specFilename, true)
			if err != nil {
				return fmt.Errorf("failed computing component files %q: %w", specFilename, err)
			}
			checkFn, err = install.SkipComponentsPathWithSubpathsFn(allowedPaths)
			if err != nil {
				return fmt.Errorf("failed compiling skip fn %q: %w", specFilename, err)
			}

			source = filepath.Dir(source)
			target = filepath.Dir(target)
		}

		if err := CopyWithCheck(source, target, checkFn); err != nil {
			if f.SkipOnMissing && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("failed to copy from %s to %s: %w", f.Source, target, err)
		}
	}
	return nil
}

func (b *dockerBuilderNoTemplate) prepareBuild() error {
	elasticBeatsDir, err := ElasticBeatsDir()
	if err != nil {
		return err
	}

	// Copy the non-templated Dockerfile
	dockerDir := filepath.Join(elasticBeatsDir, "dev-tools/packaging/docker")
	dockerfileSrc := filepath.Join(dockerDir, "Dockerfile.elastic-agent")
	dockerfileDst := filepath.Join(b.buildDir, "Dockerfile")

	if err := Copy(dockerfileSrc, dockerfileDst); err != nil {
		return fmt.Errorf("copying Dockerfile: %w", err)
	}

	// Copy the appropriate entrypoint script based on variant
	var entrypointSrc string
	switch b.DockerVariant {
	case EdotCollector, EdotCollectorWolfi:
		entrypointSrc = filepath.Join(dockerDir, "docker-entrypoint.edot.sh")
	default:
		entrypointSrc = filepath.Join(dockerDir, "docker-entrypoint.elastic-agent.sh")
	}
	entrypointDst := filepath.Join(b.buildDir, "docker-entrypoint")

	if err := Copy(entrypointSrc, entrypointDst); err != nil {
		return fmt.Errorf("copying entrypoint: %w", err)
	}

	// Make entrypoint executable
	if err := os.Chmod(entrypointDst, 0755); err != nil {
		return fmt.Errorf("chmod entrypoint: %w", err)
	}

	return nil
}

// getBuildArgs returns the build arguments to pass to docker build
func (b *dockerBuilderNoTemplate) getBuildArgs() []string {
	args := []string{}

	// Helper to expand template strings in extra vars
	expandVar := func(v string) string {
		expanded, err := b.Expand(v)
		if err != nil {
			return v // Return original if expansion fails
		}
		return expanded
	}

	// Get the base images from extra vars
	buildFrom := "cgr.dev/chainguard/wolfi-base"
	if v, ok := b.ExtraVars["buildFrom"]; ok {
		// Remove any --platform= prefix that was used in templates
		v = strings.TrimPrefix(v, "--platform=linux/amd64 ")
		v = strings.TrimPrefix(v, "--platform=linux/arm64 ")
		buildFrom = expandVar(v)
	}

	fromImage := "redhat/ubi9-minimal"
	if v, ok := b.ExtraVars["from"]; ok {
		v = strings.TrimPrefix(v, "--platform=linux/amd64 ")
		v = strings.TrimPrefix(v, "--platform=linux/arm64 ")
		fromImage = expandVar(v)
	}

	// Get commit info
	commit, _ := CommitHash()
	commitShort, _ := CommitHashShort()
	buildDate := BuildDate()
	version := b.Version
	if b.Snapshot {
		version = version + "-SNAPSHOT"
	}

	// Get repo info
	repoInfo, _ := GetProjectRepoInfo()
	vcsURL := ""
	if repoInfo != nil {
		vcsURL = repoInfo.RootImportPath
	}

	// User name - expand template if present
	userName := b.Name
	if v, ok := b.ExtraVars["user"]; ok {
		userName = expandVar(v)
	}

	// Linux capabilities
	linuxCapabilities := ""
	if v, ok := b.ExtraVars["linux_capabilities"]; ok {
		linuxCapabilities = expandVar(v)
	}

	// Add all build args
	args = append(args,
		"--build-arg", fmt.Sprintf("BUILD_FROM=%s", buildFrom),
		"--build-arg", fmt.Sprintf("FROM_IMAGE=%s", fromImage),
		"--build-arg", fmt.Sprintf("BEAT_NAME=%s", b.Name),
		"--build-arg", fmt.Sprintf("BEAT_VERSION=%s", version),
		"--build-arg", fmt.Sprintf("BEAT_SNAPSHOT=%t", b.Snapshot),
		"--build-arg", fmt.Sprintf("BEAT_VENDOR=%s", b.Vendor),
		"--build-arg", fmt.Sprintf("BEAT_LICENSE=%s", b.License),
		"--build-arg", fmt.Sprintf("BEAT_URL=%s", b.URL),
		"--build-arg", fmt.Sprintf("BEAT_DESCRIPTION=%s", b.Description),
		"--build-arg", fmt.Sprintf("COMMIT=%s", commit),
		"--build-arg", fmt.Sprintf("COMMIT_SHORT=%s", commitShort),
		"--build-arg", fmt.Sprintf("BUILD_DATE=%s", buildDate),
		"--build-arg", fmt.Sprintf("VCS_URL=%s", vcsURL),
		"--build-arg", fmt.Sprintf("USER_NAME=%s", userName),
		"--build-arg", fmt.Sprintf("LINUX_CAPABILITIES=%s", linuxCapabilities),
		"--build-arg", fmt.Sprintf("VARIANT=%s", b.DockerVariant.String()),
	)

	return args
}

func (b *dockerBuilderNoTemplate) dockerBuild() (string, []string, error) {
	platform := fmt.Sprintf("%s/%s", "linux", b.Arch)
	tagSuffix := ""
	args := []string{
		"build",
	}
	if runtime.GOARCH != b.Arch {
		if !b.isBuildxEnabled {
			return "", nil, fmt.Errorf("cross-platform docker build requested, but buildx is not available")
		}
		tagSuffix = "-" + b.Arch
		args = append(args, "--platform", platform)
	}

	mainTag := fmt.Sprintf("%s:%s", b.imageName, b.Version)
	mainTag = strings.Replace(mainTag, "+", ".", 1)
	if b.Snapshot {
		mainTag = mainTag + "-SNAPSHOT"
	}

	if repository := b.ExtraVars["repository"]; repository != "" {
		mainTag = fmt.Sprintf("%s/%s", repository, mainTag)
	}

	if tagSuffix != "" {
		mainTag = mainTag + tagSuffix
	}

	args = append(args, "-t", mainTag)

	extraTags := []string{}
	for _, tag := range b.ExtraTags {
		extraTag := fmt.Sprintf("%s:%s", b.imageName, tag)
		if tagSuffix != "" {
			extraTag = extraTag + tagSuffix
		}
		extraTags = append(extraTags, extraTag)
	}
	for _, t := range extraTags {
		args = append(args, "-t", t)
	}

	// Add build args
	args = append(args, b.getBuildArgs()...)

	args = append(args, b.buildDir)

	if mg.Verbose() {
		log.Printf("Running: docker %s", strings.Join(args, " "))
	}

	return mainTag, extraTags, sh.Run("docker", args...)
}

func (b *dockerBuilderNoTemplate) dockerSave(tag string, templateExtraArgs ...map[string]interface{}) error {
	if _, err := os.Stat(distributionsDir); os.IsNotExist(err) {
		err := os.MkdirAll(distributionsDir, 0750)
		if err != nil {
			return fmt.Errorf("cannot create folder for docker artifacts: %w", err)
		}
	}

	outputFile := b.OutputFile
	if outputFile == "" {
		args := map[string]interface{}{
			"Name": b.imageName,
		}
		for _, extraArgs := range templateExtraArgs {
			maps.Copy(args, extraArgs)
		}
		outputTar, err := b.Expand(defaultBinaryName+".docker.tar.gz", args)
		if err != nil {
			return err
		}
		outputFile = filepath.Join(distributionsDir, outputTar)
	}

	if mg.Verbose() {
		log.Printf(">>>> saving docker image %s to %s", tag, outputFile)
	}

	var stderr bytes.Buffer
	cmd := exec.Command("docker", "save", tag)
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}

	err = func() error {
		f, err := os.Create(outputFile)
		if err != nil {
			return err
		}
		defer f.Close()

		w := gzip.NewWriter(f)
		defer w.Close()

		_, err = io.Copy(w, stdout)
		if err != nil {
			return err
		}
		return nil
	}()
	if err != nil {
		return err
	}

	if err = cmd.Wait(); err != nil {
		if errmsg := strings.TrimSpace(stderr.String()); errmsg != "" {
			err = fmt.Errorf("%w: %s", errors.New(errmsg), err.Error())
		}
		return err
	}

	err = CreateSHA512File(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create .sha512 file: %w", err)
	}
	return nil
}
