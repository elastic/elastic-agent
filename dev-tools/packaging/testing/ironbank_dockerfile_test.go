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
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	dockerclient "github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// publicUBIRegistry is the registry used when building the Ironbank Dockerfile
// in environments that cannot reach the restricted Ironbank registry.
const publicUBIRegistry = "registry.access.redhat.com"

// publicUBIImage is the public Red Hat UBI image path that is functionally
// equivalent to the Ironbank "redhat/ubi/ubi10" image.
const publicUBIImage = "ubi10/ubi"

func TestIronbankDockerfilePermissions(t *testing.T) {
	cli, err := dockerclient.New(dockerclient.FromEnv)
	require.NoError(t, err)
	t.Cleanup(func() { cli.Close() })

	if _, err := cli.Ping(t.Context(), dockerclient.PingOptions{}); err != nil {
		t.Skipf("docker daemon not accessible: %v", err)
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
		_, _ = cli.ImageRemove(context.Background(), imageTag, dockerclient.ImageRemoveOptions{Force: true, PruneChildren: true})
	})

	buildCtxTar, err := dirTar(buildCtx)
	require.NoError(t, err)

	buildResp, err := cli.ImageBuild(t.Context(), buildCtxTar, dockerclient.ImageBuildOptions{
		Tags:   []string{imageTag},
		Remove: true,
		BuildArgs: map[string]*string{
			"BASE_REGISTRY": strPtr(publicUBIRegistry),
			"BASE_IMAGE":    strPtr(publicUBIImage),
			"BASE_TAG":      strPtr(baseTag),
			"ELASTIC_STACK": strPtr(testVersion),
			"OS_AND_ARCH":   strPtr(testOSArch),
		},
	})
	require.NoError(t, err)
	defer buildResp.Body.Close()
	require.NoError(t, consumeBuildOutput(buildResp.Body), "docker build failed")

	out, err := runContainerOneShot(t.Context(), cli, imageTag,
		"/bin/sh", []string{"-c",
			`find /usr/share/elastic-agent/data/elastic-agent-*/components -name "*.yml" -type f -exec stat -c '%n %a' {} \;`,
		},
	)
	require.NoError(t, err)

	var ymlFiles []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
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
func renderIronbankDockerfile(t *testing.T, tmplPath, buildCtx, version string) {
	t.Helper()
	content, err := os.ReadFile(tmplPath)
	require.NoError(t, err, "reading Ironbank Dockerfile template")

	rendered := strings.ReplaceAll(string(content), "{{ agent_package_version }}", version)

	dest := filepath.Join(buildCtx, "Dockerfile")
	//nolint:gosec // dest is filepath.Join of a t.TempDir() path — no traversal possible
	require.NoError(t, os.WriteFile(dest, []byte(rendered), 0o644))
}

// createFakeAgentTarball creates a minimal elastic-agent tar.gz in buildCtx
// that satisfies the COPY and chmod commands in the Ironbank Dockerfile.
//
// The tarball has one top-level directory (stripped by --strip-components=1)
// and the following paths underneath it:
//
//	elastic-agent                                                  (stub binary)
//	data/<versionedHome>/elastic-agent                             (stub binary)
//	data/<versionedHome>/components/filebeat                       (stub, satisfies *beat glob)
//	data/<versionedHome>/components/module/kafka/module.yml        (must be 0644 after build)
func createFakeAgentTarball(t *testing.T, buildCtx, product, version, osArch, versionedHome string) {
	t.Helper()

	tarName := product + "-" + version + "-" + osArch + ".tar.gz"
	tarPath := filepath.Join(buildCtx, tarName)

	topLevel := product + "-" + version + "-" + osArch

	type entry struct {
		name  string
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

// dirTar creates an uncompressed tar archive of all files under dir, with
// paths relative to dir (no leading path component). The result is suitable
// for use as a Docker image build context.
func dirTar(dir string) (io.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		hdr := &tar.Header{
			Name: filepath.ToSlash(rel),
			Mode: int64(info.Mode()),
		}
		if d.IsDir() {
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
			return tw.WriteHeader(hdr)
		}

		hdr.Typeflag = tar.TypeReg
		hdr.Size = info.Size()
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		//nolint:gosec // path comes from WalkDir over a temp directory we own; no TOCTOU risk
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}

// buildOutputMsg is the subset of Docker's streaming build JSON we care about.
type buildOutputMsg struct {
	Stream string `json:"stream"`
	Error  string `json:"error"`
}

// consumeBuildOutput drains the streaming JSON from an image build response
// body, returning a non-nil error if Docker reported a build failure.
func consumeBuildOutput(r io.Reader) error {
	dec := json.NewDecoder(r)
	for {
		var msg buildOutputMsg
		if err := dec.Decode(&msg); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		if msg.Error != "" {
			return fmt.Errorf("%s", strings.TrimRight(msg.Error, "\n"))
		}
	}
}

// runContainerOneShot creates a container from image, runs entrypoint with cmd,
// waits for it to exit, returns its stdout, then removes the container.
func runContainerOneShot(ctx context.Context, cli *dockerclient.Client, image, entrypoint string, cmd []string) ([]byte, error) {
	created, err := cli.ContainerCreate(ctx, dockerclient.ContainerCreateOptions{
		Config: &container.Config{
			Image:      image,
			Entrypoint: []string{entrypoint},
			Cmd:        cmd,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("ContainerCreate: %w", err)
	}

	waitResult := cli.ContainerWait(ctx, created.ID, dockerclient.ContainerWaitOptions{
		Condition: container.WaitConditionNotRunning,
	})

	if _, err := cli.ContainerStart(ctx, created.ID, dockerclient.ContainerStartOptions{}); err != nil {
		return nil, fmt.Errorf("ContainerStart: %w", err)
	}

	select {
	case res := <-waitResult.Result:
		if res.Error != nil {
			return nil, fmt.Errorf("container exited with error: %s", res.Error.Message)
		}
		if res.StatusCode != 0 {
			return nil, fmt.Errorf("container exited with status %d", res.StatusCode)
		}
	case err := <-waitResult.Error:
		return nil, fmt.Errorf("ContainerWait: %w", err)
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	defer func() {
		_, _ = cli.ContainerRemove(context.Background(), created.ID,
			dockerclient.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	}()

	logs, err := cli.ContainerLogs(ctx, created.ID, dockerclient.ContainerLogsOptions{
		ShowStdout: true,
	})
	if err != nil {
		return nil, fmt.Errorf("ContainerLogs: %w", err)
	}
	defer logs.Close()

	return readDockerStdout(logs)
}

// readDockerStdout demultiplexes a Docker log stream (8-byte frame header
// followed by payload) and returns only the stdout frames.
// Frame header: [stream_type(1), padding(3), payload_size(4 big-endian)].
// stream_type 1 = stdout, 2 = stderr.
func readDockerStdout(r io.Reader) ([]byte, error) {
	var out bytes.Buffer
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			return nil, err
		}
		size := int64(binary.BigEndian.Uint32(hdr[4:]))
		if hdr[0] == 1 { // stdout
			if _, err := io.CopyN(&out, r, size); err != nil {
				return nil, err
			}
		} else {
			if _, err := io.CopyN(io.Discard, r, size); err != nil {
				return nil, err
			}
		}
	}
	return out.Bytes(), nil
}

func writeFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, content, mode))
}

func strPtr(s string) *string { return &s }
