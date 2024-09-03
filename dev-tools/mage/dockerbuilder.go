// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mage

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/magefile/mage/sh"
)

type dockerBuilder struct {
	PackageSpec

	imageName string
	buildDir  string
	beatDir   string
}

func newDockerBuilder(spec PackageSpec) (*dockerBuilder, error) {
	buildDir := filepath.Join(spec.packageDir, "docker-build")
	beatDir := filepath.Join(buildDir, "beat")

	return &dockerBuilder{
		PackageSpec: spec,
		imageName:   spec.ImageName(),
		buildDir:    buildDir,
		beatDir:     beatDir,
	}, nil
}

func (b *dockerBuilder) Build() error {
	if err := os.RemoveAll(b.buildDir); err != nil {
		return fmt.Errorf("failed to clean existing build directory %s: %w", b.buildDir, err)
	}

	if err := b.copyFiles(); err != nil {
		return err
	}

	if err := b.prepareBuild(); err != nil {
		return fmt.Errorf("failed to prepare build: %w", err)
	}

	tag, err := b.dockerBuild()
	tries := 3
	for err != nil && tries != 0 {
		fmt.Println(">> Building docker images again (after 10 s)")
		// This sleep is to avoid hitting the docker build issues when resources are not available.
		time.Sleep(time.Second * 10)
		tag, err = b.dockerBuild()
		tries--
	}
	if err != nil {
		return fmt.Errorf("failed to build docker: %w", err)
	}

	if err := b.dockerSave(tag); err != nil {
		return fmt.Errorf("failed to save docker as artifact: %w", err)
	}

	return nil
}

func (b *dockerBuilder) modulesDirs() []string {
	var modulesd []string
	for _, f := range b.Files {
		if f.Modules {
			modulesd = append(modulesd, f.Target)
		}
	}
	return modulesd
}

func (b *dockerBuilder) exposePorts() []string {
	if ports := b.ExtraVars["expose_ports"]; ports != "" {
		return strings.Split(ports, ",")
	}
	return nil
}

func (b *dockerBuilder) copyFiles() error {
	for _, f := range b.Files {
		target := filepath.Join(b.beatDir, f.Target)
		if err := Copy(f.Source, target); err != nil {
			if f.SkipOnMissing && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("failed to copy from %s to %s: %w", f.Source, target, err)
		}
	}
	return nil
}

func (b *dockerBuilder) prepareBuild() error {
	elasticBeatsDir, err := ElasticBeatsDir()
	if err != nil {
		return err
	}
	templatesDir := filepath.Join(elasticBeatsDir, "dev-tools/packaging/templates/docker")

	data := map[string]interface{}{
		"ExposePorts": b.exposePorts(),
		"ModulesDirs": b.modulesDirs(),
		"Variant":     b.DockerVariant.String(),
	}

	err = filepath.Walk(templatesDir, func(path string, info os.FileInfo, _ error) error {
		if !info.IsDir() && !isDockerFile(path) {
			target := strings.TrimSuffix(
				filepath.Join(b.buildDir, filepath.Base(path)),
				".tmpl",
			)

			err = b.ExpandFile(path, target, data)
			if err != nil {
				return fmt.Errorf("expanding template '%s' to '%s': %w", path, target, err)
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	return b.expandDockerfile(templatesDir, data)
}

func isDockerFile(path string) bool {
	path = filepath.Base(path)
	return strings.HasPrefix(path, "Dockerfile") || strings.HasPrefix(path, "docker-entrypoint")
}

func (b *dockerBuilder) expandDockerfile(templatesDir string, data map[string]interface{}) error {
	dockerfile := "Dockerfile.tmpl"
	if f, found := b.ExtraVars["dockerfile"]; found {
		dockerfile = f
	}

	entrypoint := "docker-entrypoint.tmpl"
	if e, found := b.ExtraVars["docker_entrypoint"]; found {
		entrypoint = e
	}

	type fileExpansion struct {
		source string
		target string
	}
	for _, file := range []fileExpansion{{dockerfile, "Dockerfile.tmpl"}, {entrypoint, "docker-entrypoint.tmpl"}} {
		target := strings.TrimSuffix(
			filepath.Join(b.buildDir, file.target),
			".tmpl",
		)
		path := filepath.Join(templatesDir, file.source)
		err := b.ExpandFile(path, target, data)
		if err != nil {
			return fmt.Errorf("expanding template '%s' to '%s': %w", path, target, err)
		}
	}

	return nil
}

func (b *dockerBuilder) dockerBuild() (string, error) {
	tag := fmt.Sprintf("%s:%s", b.imageName, b.Version)
	// For Independent Agent releases, replace the "+" with a "." since the "+" character
	// currently isn't allowed in a tag in Docker
	// E.g., 8.13.0+build202402191057 -> 8.13.0.build202402191057
	tag = strings.Replace(tag, "+", ".", 1)
	if b.Snapshot {
		tag = tag + "-SNAPSHOT"
	}
	if repository := b.ExtraVars["repository"]; repository != "" {
		tag = fmt.Sprintf("%s/%s", repository, tag)
	}
	return tag, sh.Run("docker", "build", "-t", tag, b.buildDir)
}

func (b *dockerBuilder) dockerSave(tag string) error {
	if _, err := os.Stat(distributionsDir); os.IsNotExist(err) {
		err := os.MkdirAll(distributionsDir, 0750)
		if err != nil {
			return fmt.Errorf("cannot create folder for docker artifacts: %w", err)
		}
	}
	// Save the container as artifact
	outputFile := b.OutputFile
	if outputFile == "" {
		outputTar, err := b.Expand(defaultBinaryName+".docker.tar.gz", map[string]interface{}{
			"Name": b.imageName,
		})
		if err != nil {
			return err
		}
		outputFile = filepath.Join(distributionsDir, outputTar)
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
