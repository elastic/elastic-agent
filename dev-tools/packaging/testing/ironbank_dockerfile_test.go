// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

// TestIronbankDockerfilePermissions builds the Ironbank Dockerfile template
// using a publicly accessible UBI base image in place of the Ironbank registry
// (which requires privileged repository access) and verifies that .yml files
// inside components/ are restored to 0644 permissions after the broad 0666
// chmod applied earlier in the RUN layer.
//
// Run with:
//
//	go test -v -run TestIronbankDockerfilePermissions ./dev-tools/packaging/testing/

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// publicUBIRegistry is the registry used when building the Ironbank Dockerfile
// in CI environments that cannot reach the restricted Ironbank registry.
const publicUBIRegistry = "registry.access.redhat.com"

// publicUBIImage is the public Red Hat UBI image path that is functionally
// equivalent to the Ironbank "redhat/ubi/ubi10" image.
const publicUBIImage = "ubi10/ubi"

func TestIronbankDockerfilePermissions(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH")
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon not accessible: %v\n%s", err, out)
	}

	const (
		testVersion = "0.0.1-test"
		testOSArch  = "linux-x86_64"
		testProduct = "elastic-agent"
	)

	versionedHome := testProduct + "-" + testVersion

	tmplPath := filepath.Join(*sourceRoot, "templates/ironbank/Dockerfile.tmpl")
	baseTag := parseDockerfileArg(t, tmplPath, "BASE_TAG")

	buildCtx := t.TempDir()

	renderIronbankDockerfile(t, tmplPath, buildCtx, testVersion)
	createFakeAgentTarball(t, buildCtx, testProduct, testVersion, testOSArch, versionedHome)
	writeFile(t, filepath.Join(buildCtx, "tinit"), []byte("#!/bin/sh\n"), 0o755)
	writeFile(t, filepath.Join(buildCtx, "jq"), []byte("#!/bin/sh\n"), 0o755)
	require.NoError(t, os.MkdirAll(filepath.Join(buildCtx, "config"), 0o755))
	writeFile(t, filepath.Join(buildCtx, "config", "docker-entrypoint"), []byte("#!/bin/sh\nexec \"$@\"\n"), 0o755)
	writeFile(t, filepath.Join(buildCtx, "LICENSE"), []byte("LICENSE\n"), 0o644)

	imageTag := "elastic-agent-ironbank-perms-test:latest"
	t.Cleanup(func() {
		//nolint:errcheck
		exec.Command("docker", "rmi", "-f", imageTag).Run()
	})

	buildOut, err := exec.Command("docker", "build",
		"--build-arg", "BASE_REGISTRY="+publicUBIRegistry,
		"--build-arg", "BASE_IMAGE="+publicUBIImage,
		"--build-arg", "BASE_TAG="+baseTag,
		"--build-arg", "ELASTIC_STACK="+testVersion,
		"--build-arg", "OS_AND_ARCH="+testOSArch,
		"-t", imageTag,
		buildCtx,
	).CombinedOutput()
	require.NoError(t, err, "docker build failed:\n%s", buildOut)

	runOut, err := exec.Command("docker", "run", "--rm", "--entrypoint", "/bin/sh", imageTag,
		"-c", `find /usr/share/elastic-agent/data/elastic-agent-*/components -name "*.yml" -type f -exec stat -c '%n %a' {} \;`,
	).Output()
	require.NoError(t, err, "docker run failed: %v", err)

	var ymlFiles []string
	scanner := bufio.NewScanner(bytes.NewReader(runOut))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		require.Lenf(t, parts, 2, "unexpected stat output line: %q", line)
		name, perm := parts[0], parts[1]
		ymlFiles = append(ymlFiles, name)
		assert.Equalf(t, "644", perm, "file %s has wrong permissions: want 644, got %s", name, perm)
	}
	assert.NotEmptyf(t, ymlFiles, "no .yml files found under components in %s image", imageTag)
}

// parseDockerfileArg reads the default value of a Docker ARG from a Dockerfile
// (or Dockerfile template), returning the value after the "=" sign.
// It looks for lines of the form "ARG <name>=<value>".
func parseDockerfileArg(t *testing.T, dockerfilePath, argName string) string {
	t.Helper()
	data, err := os.ReadFile(dockerfilePath)
	require.NoError(t, err, "reading %s", dockerfilePath)

	prefix := fmt.Sprintf("ARG %s=", argName)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	t.Fatalf("ARG %s not found in %s", argName, dockerfilePath)
	return ""
}

// renderIronbankDockerfile reads the Ironbank Dockerfile.tmpl, substitutes the
// single Go template variable {{ agent_package_version }} with version, and
// writes the result as "Dockerfile" into buildCtx.
//
// All other "${ ... }" references in the file are Docker build ARGs and are
// left untouched; they are supplied via --build-arg at docker-build time.
func renderIronbankDockerfile(t *testing.T, tmplPath, buildCtx, version string) {
	t.Helper()
	content, err := os.ReadFile(tmplPath)
	require.NoError(t, err, "reading Ironbank Dockerfile template")

	rendered := strings.ReplaceAll(string(content), "{{ agent_package_version }}", version)

	dest := filepath.Join(buildCtx, "Dockerfile")
	require.NoError(t, os.WriteFile(dest, []byte(rendered), 0o644))
}

// createFakeAgentTarball creates a minimal elastic-agent tar.gz in buildCtx
// that satisfies the COPY and chmod commands in the Ironbank Dockerfile.
//
// The tarball has one top-level directory (stripped by --strip-components=1)
// and the following paths underneath it:
//
//	elastic-agent                                     (stub binary)
//	data/<versionedHome>/elastic-agent                (stub binary)
//	data/<versionedHome>/components/filebeat          (stub binary, satisfies *beat glob)
//	data/<versionedHome>/components/module/kafka/module.yml  (config, must be 0644 after build)
func createFakeAgentTarball(t *testing.T, buildCtx, product, version, osArch, versionedHome string) {
	t.Helper()

	tarName := product + "-" + version + "-" + osArch + ".tar.gz"
	tarPath := filepath.Join(buildCtx, tarName)

	topLevel := product + "-" + version + "-" + osArch

	type entry struct {
		name  string // path relative to topLevel/
		isDir bool
		mode  int64
		body  []byte
	}

	stubBin := []byte("#!/bin/sh\n")
	entries := []entry{
		{name: "", isDir: true, mode: 0o755},
		{name: "data", isDir: true, mode: 0o755},
		{name: "data/" + versionedHome, isDir: true, mode: 0o755},
		{name: "data/" + versionedHome + "/components", isDir: true, mode: 0o755},
		{name: "data/" + versionedHome + "/components/module", isDir: true, mode: 0o755},
		{name: "data/" + versionedHome + "/components/module/kafka", isDir: true, mode: 0o755},
		{name: product, mode: 0o755, body: stubBin},
		{name: "data/" + versionedHome + "/" + product, mode: 0o755, body: stubBin},
		{name: "data/" + versionedHome + "/components/filebeat", mode: 0o755, body: stubBin},
		{name: "data/" + versionedHome + "/components/module/kafka/module.yml", mode: 0o644, body: []byte("module: kafka\n")},
	}

	f, err := os.Create(tarPath)
	require.NoError(t, err)

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	for _, e := range entries {
		fullName := topLevel
		if e.name != "" {
			fullName += "/" + e.name
		}
		if e.isDir {
			require.NoError(t, tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir,
				Name:     fullName + "/",
				Mode:     e.mode,
			}))
		} else {
			require.NoError(t, tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeReg,
				Name:     fullName,
				Mode:     e.mode,
				Size:     int64(len(e.body)),
			}))
			_, err = tw.Write(e.body)
			require.NoError(t, err)
		}
	}

	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, f.Close())
}

func writeFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, content, mode))
}
