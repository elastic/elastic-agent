// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

// TestIronbankDockerfilePermissions builds the Ironbank Dockerfile using a
// publicly accessible UBI base image in place of the restricted Ironbank
// registry and verifies that .yml files inside components/ are restored to
// 0644 permissions after the broad 0666 chmod applied earlier in the RUN layer.
//
// The test uses pre-built artifacts from build/distributions/:
//   - the ironbank docker build context tarball (*-ironbank-*-docker-build-context.tar.gz)
//   - the linux x86_64 agent tarball (elastic-agent-*-linux-x86_64.tar.gz)
//
// Run after 'mage Package Ironbank':
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
	"regexp"
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

	distDir := filepath.Join(*sourceRoot, "../build/distributions")

	ironbankCtxFile := findFile(t, distDir, regexp.MustCompile(`-ironbank-.*-docker-build-context\.tar\.gz$`))
	if ironbankCtxFile == "" {
		t.Skip("no ironbank docker build context found in build/distributions; run 'mage Ironbank' first")
	}

	agentTarball := findFile(t, distDir, regexp.MustCompile(`^elastic-agent-[\d.].*-linux-x86_64\.tar\.gz$`))
	if agentTarball == "" {
		t.Skip("no elastic-agent linux-x86_64 tarball found in build/distributions; run 'mage Package' first")
	}

	// Parse version and OS/arch from the agent tarball filename.
	// e.g. "elastic-agent-8.18.0-SNAPSHOT-linux-x86_64.tar.gz" → version="8.18.0-SNAPSHOT", osArch="linux-x86_64"
	const osArch = "linux-x86_64"
	base := strings.TrimSuffix(filepath.Base(agentTarball), ".tar.gz")
	version := strings.TrimSuffix(strings.TrimPrefix(base, "elastic-agent-"), "-"+osArch)

	buildCtx := t.TempDir()

	// Extract the ironbank docker build context (Dockerfile, config/, LICENSE).
	require.NoError(t, extractTarGz(ironbankCtxFile, buildCtx))

	// The Dockerfile COPYs the agent tarball; it must be present in the build context.
	dst := filepath.Join(buildCtx, "elastic-agent-"+version+"-"+osArch+".tar.gz")
	require.NoError(t, copyFile(agentTarball, dst))

	// tinit and jq are provided by the IronBank pipeline; add minimal stubs here.
	writeFile(t, filepath.Join(buildCtx, "tinit"), []byte("#!/bin/sh\n"), 0o755)
	writeFile(t, filepath.Join(buildCtx, "jq"), []byte("#!/bin/sh\n"), 0o755)

	baseTag := parseDockerfileArg(t, filepath.Join(buildCtx, "Dockerfile"), "BASE_TAG")

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
			"ELASTIC_STACK": strPtr(version),
			"OS_AND_ARCH":   strPtr(osArch),
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

// findFile returns the path of the first file in dir matching pattern,
// or empty string if none is found.
func findFile(t *testing.T, dir string, pattern *regexp.Regexp) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return ""
	}
	require.NoError(t, err)
	for _, e := range entries {
		if !e.IsDir() && pattern.MatchString(e.Name()) {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

// extractTarGz extracts a .tar.gz file into destDir.
func extractTarGz(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		rel := filepath.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if rel == "." {
			continue
		}
		dest := filepath.Join(destDir, rel)

		//nolint:gosec // G115: hdr.Mode is a POSIX mode stored as int64; upper bits are always 0 in valid archives
		mode := fs.FileMode(uint32(hdr.Mode))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, mode); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			//nolint:gosec // G110: src is our own build artifact, not user-supplied input
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	return nil
}

// copyFile copies a file from src to dst, preserving mode bits.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
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
