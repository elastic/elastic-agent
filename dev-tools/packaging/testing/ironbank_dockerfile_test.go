// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

// TestIronbankDockerfilePermissions loads the pre-built Ironbank Docker image
// (produced by 'DOCKER_VARIANTS=ironbank PACKAGES=docker mage package') and
// verifies that .yml files inside components/ are restored to 0644 permissions
// after the broad 0666 chmod applied earlier in the RUN layer.
//
// The image is built using the public Red Hat registry in place of the
// restricted Ironbank registry, so this test runs in standard CI without
// privileged registry access.
//
// Run after 'DOCKER_VARIANTS=ironbank PACKAGES=docker mage package':
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

func TestIronbankDockerfilePermissions(t *testing.T) {
	cli, err := dockerclient.New(dockerclient.FromEnv)
	require.NoError(t, err)
	t.Cleanup(func() { cli.Close() })

	if _, err := cli.Ping(t.Context(), dockerclient.PingOptions{}); err != nil {
		t.Skipf("docker daemon not accessible: %v", err)
	}

	distDir := filepath.Join(*sourceRoot, "../build/distributions")

	// Find the ironbank Docker image produced by DOCKER_VARIANTS=ironbank mage package.
	imageFile := findFile(t, distDir, regexp.MustCompile(`-ironbank-.*\.docker\.tar\.gz$`))
	if imageFile == "" {
		t.Skip("no ironbank docker image found in build/distributions; run 'DOCKER_VARIANTS=ironbank PACKAGES=docker mage package' first")
	}

	imageTag, err := loadDockerImage(t.Context(), cli, imageFile)
	require.NoError(t, err, "loading ironbank docker image")
	t.Cleanup(func() {
		_, _ = cli.ImageRemove(context.Background(), imageTag, dockerclient.ImageRemoveOptions{Force: true, PruneChildren: true})
	})

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

// loadDockerImage loads a gzip-compressed Docker image tar into the daemon and
// returns the first image reference (repository:tag) embedded in the archive.
func loadDockerImage(ctx context.Context, cli *dockerclient.Client, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gr.Close()

	resp, err := cli.ImageLoad(ctx, gr)
	if err != nil {
		return "", fmt.Errorf("ImageLoad: %w", err)
	}
	defer resp.Close()
	if _, err := io.Copy(io.Discard, resp); err != nil {
		return "", fmt.Errorf("draining ImageLoad response: %w", err)
	}

	// Re-open to read the manifest embedded in the tar for the image reference.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	gr2, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gr2.Close()
	return readImageRefFromTar(gr2)
}

// readImageRefFromTar walks a Docker image tar looking for manifest.json and
// returns the first RepoTag entry it finds.
func readImageRefFromTar(r io.Reader) (string, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if hdr.Name != "manifest.json" {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return "", err
		}
		var manifests []struct {
			RepoTags []string `json:"RepoTags"`
		}
		if err := json.Unmarshal(data, &manifests); err != nil {
			return "", fmt.Errorf("parsing manifest.json: %w", err)
		}
		if len(manifests) > 0 && len(manifests[0].RepoTags) > 0 {
			return manifests[0].RepoTags[0], nil
		}
		return "", fmt.Errorf("manifest.json has no RepoTags")
	}
	return "", fmt.Errorf("manifest.json not found in docker image tar")
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
