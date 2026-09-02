// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package docker provides an InstanceProvisioner that runs each test batch in a
// local, systemd-enabled Docker container instead of a VM. Because the container
// runs systemd as PID 1 and sshd, the existing Linux test runner drives it over SSH
// exactly like a VM, including the Elastic Agent's systemd service install. This
// lets the privileged ("sudo") integration tests run locally without provisioning a
// cloud VM.
package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	dockerclient "github.com/moby/moby/client"
	"golang.org/x/mod/modfile"

	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
)

const (
	// Name is the name of the docker instance provisioner.
	Name = "docker"
	// Ubuntu is the only distro currently supported.
	Ubuntu = "ubuntu"

	// containerNamePrefix namespaces the containers created by this provisioner.
	containerNamePrefix = "eat-it-"
	// containerLabel tags every container this provisioner creates so leftovers
	// (e.g. from a run cancelled mid-provision, before they were saved to state)
	// can be found and removed during cleanup.
	containerLabel = "elastic-agent-integration-test"
	// imageRepo is the local image repository for the built systemd images.
	imageRepo = "elastic-agent-test-systemd"
	// sshUser is the user the test runner connects as (created in the image).
	sshUser = "ubuntu"

	// containerModCacheDownload is where the host's Go module download cache is
	// mounted (read-only) inside the container. It is exposed to Go as a file://
	// module proxy so module fetches resolve from the host's existing cache instead
	// of re-downloading over the network. Go still unpacks modules into the
	// container's own (writable) module cache, so a read-only mount is safe here.
	containerModCacheDownload = "/var/cache/go-mod-download"

	// mageModule and gotestsumModule are the build tools baked into the image,
	// pinned to the versions in the repo's go.mod (read at provision time).
	mageModule      = "github.com/magefile/mage"
	gotestsumModule = "gotest.tools/gotestsum"
)

//go:embed Dockerfile
var dockerfile []byte

type provisioner struct {
	logger common.Logger
	client *dockerclient.Client
}

// NewProvisioner creates the docker instance provisioner.
func NewProvisioner() common.InstanceProvisioner {
	return &provisioner{}
}

func (p *provisioner) Name() string {
	return Name
}

func (p *provisioner) SetLogger(l common.Logger) {
	p.logger = l
}

func (p *provisioner) Type() common.ProvisionerType {
	return common.ProvisionerTypeVM
}

// Supported returns true if the docker provisioner supports this OS.
//
// Only Ubuntu on the same architecture as the host is supported: the container
// shares the host kernel (so the architecture must match) and the Linux runner
// targets Debian/Ubuntu.
func (p *provisioner) Supported(os define.OS) bool {
	if os.Type != define.Linux {
		return false
	}
	if os.Distro != Ubuntu {
		return false
	}
	if os.Arch != runtime.GOARCH {
		return false
	}
	return true
}

func (p *provisioner) Provision(ctx context.Context, cfg common.Config, batches []common.OSBatch) ([]common.Instance, error) {
	// The runner reaches sshd on the container's bridge IP at port 22, which only
	// works when the host can route to the docker bridge (i.e. a Linux host). On
	// macOS the container IP isn't routable and the SSH port would have to be
	// published, which the test framework's SSH client doesn't support yet.
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("the %q instance provisioner currently supports Linux hosts only "+
			"(macOS would require publishing the SSH port); host is %s", Name, runtime.GOOS)
	}
	if err := p.checkDocker(ctx); err != nil {
		return nil, err
	}

	publicKeyPath := filepath.Join(cfg.StateDir, "id_rsa.pub")
	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH public key at %s: %w", publicKeyPath, err)
	}

	if cfg.GOVersion == "" {
		return nil, fmt.Errorf("the %q instance provisioner requires a Go version to bake into the image", Name)
	}

	tools, err := toolVersions(cfg.RepoDir)
	if err != nil {
		return nil, err
	}
	build := imageBuild{
		goVersion:        cfg.GOVersion,
		mageVersion:      tools.mage,
		gotestsumVersion: tools.gotestsum,
	}

	// Best-effort: share the host's Go module download cache with the containers as
	// a read-only file:// proxy to avoid re-downloading modules. Empty if the host
	// cache can't be located, in which case the containers just use the network.
	modCache := hostGoModCacheDownload(ctx)
	if modCache == "" {
		p.logger.Logf("Host Go module cache not found; containers will download modules over the network")
	}

	var results []common.Instance
	for _, batch := range batches {
		instance, err := p.launch(ctx, batch, build, publicKey, modCache)
		if err != nil {
			return nil, fmt.Errorf("instance %s failed: %w", batch.ID, err)
		}
		results = append(results, instance)
	}
	return results, nil
}

// imageBuild captures the versions baked into the systemd image.
type imageBuild struct {
	goVersion        string
	mageVersion      string
	gotestsumVersion string
}

// toolVersions reads the mage and gotestsum versions pinned in the repo's go.mod so
// the image bakes in exactly what the runner installs at test time (a cache hit at
// runtime). They are required entries, so a missing one is an error.
func toolVersions(repoDir string) (struct{ mage, gotestsum string }, error) {
	var out struct{ mage, gotestsum string }
	if repoDir == "" {
		repoDir = "."
	}
	goModPath := filepath.Join(repoDir, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return out, fmt.Errorf("failed to read %s: %w", goModPath, err)
	}
	f, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return out, fmt.Errorf("failed to parse %s: %w", goModPath, err)
	}
	for _, r := range f.Require {
		switch r.Mod.Path {
		case mageModule:
			out.mage = r.Mod.Version
		case gotestsumModule:
			out.gotestsum = r.Mod.Version
		}
	}
	if out.mage == "" {
		return out, fmt.Errorf("%s does not pin %s", goModPath, mageModule)
	}
	if out.gotestsum == "" {
		return out, fmt.Errorf("%s does not pin %s", goModPath, gotestsumModule)
	}
	return out, nil
}

// hostGoModCacheDownload returns the host's Go module download cache directory
// ($GOMODCACHE/cache/download), or "" if it can't be determined or doesn't exist.
// This is the directory Go serves as a file:// module proxy, so mounting it into a
// container lets module fetches resolve from the host cache instead of the network.
func hostGoModCacheDownload(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "go", "env", "GOMODCACHE").Output()
	if err != nil {
		return ""
	}
	modcache := strings.TrimSpace(string(out))
	if modcache == "" {
		return ""
	}
	download := filepath.Join(modcache, "cache", "download")
	if fi, err := os.Stat(download); err != nil || !fi.IsDir() {
		return ""
	}
	return download
}

// Clean removes the provisioned containers. Beyond the instances recorded in state,
// it sweeps any other container this provisioner created (matched by label) so that
// leftovers from a run cancelled mid-provision — which never made it into state — are
// removed too.
func (p *provisioner) Clean(ctx context.Context, _ common.Config, instances []common.Instance) error {
	for _, instance := range instances {
		// RemoveVolumes also drops the anonymous /var/lib/docker volume backing the nested daemon.
		if _, err := p.client.ContainerRemove(ctx, instance.Name, dockerclient.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
			// don't let one failure stop the others
			p.logger.Logf("Delete container %s failed: %s", instance.Name, err)
		}
	}

	// Sweep any remaining containers this provisioner created (e.g. from a run
	// cancelled mid-provision, before being saved to state). Match by both the
	// label and the name prefix: the label is the canonical marker, the name prefix
	// also catches containers created before the label was introduced. The ones
	// removed above are already gone, so this won't double-remove them.
	leftovers := map[string]struct{}{}
	for _, f := range []dockerclient.Filters{
		make(dockerclient.Filters).Add("label", containerLabel),
		make(dockerclient.Filters).Add("name", containerNamePrefix),
	} {
		result, err := p.client.ContainerList(ctx, dockerclient.ContainerListOptions{All: true, Filters: f})
		if err != nil {
			p.logger.Logf("Listing leftover %s containers failed: %s", Name, err)
			continue
		}
		for _, c := range result.Items {
			leftovers[c.ID] = struct{}{}
		}
	}
	for id := range leftovers {
		if _, err := p.client.ContainerRemove(ctx, id, dockerclient.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
			p.logger.Logf("Delete leftover container %s failed: %s", id, err)
		}
	}
	return nil
}

// AttachInstanceToNetwork connects the instance's container to an additional docker
// network so it can reach a stack running on that network (see
// common.InstanceNetworkAttacher). It is idempotent: re-attaching an
// already-connected container is treated as success.
func (p *provisioner) AttachInstanceToNetwork(ctx context.Context, instance common.Instance, networkID string) error {
	_, err := p.client.NetworkConnect(ctx, networkID, dockerclient.NetworkConnectOptions{Container: instance.Name})
	if err != nil {
		if cerrdefs.IsConflict(err) {
			return nil
		}
		return fmt.Errorf("failed to connect container %s to network %s: %w", instance.Name, networkID, err)
	}
	return nil
}

// launch creates (or recreates) the container for a batch and returns its instance.
// modCache, when non-empty, is the host Go module download cache to share read-only.
func (p *provisioner) launch(ctx context.Context, batch common.OSBatch, bld imageBuild, publicKey []byte, modCache string) (common.Instance, error) {
	name := containerName(batch.ID)
	version := batch.OS.Version
	if version == "" {
		version = "24.04"
	}

	image, err := p.ensureImage(ctx, version, bld)
	if err != nil {
		return common.Instance{}, err
	}

	// remove any pre-existing container with the same name so the run is fresh
	// (RemoveVolumes also clears its old /var/lib/docker volume)
	_, _ = p.client.ContainerRemove(ctx, name, dockerclient.ContainerRemoveOptions{Force: true, RemoveVolumes: true})

	p.logger.Logf("Starting container %s (%s)", name, image)

	hostCfg := &container.HostConfig{
		// systemd as PID 1 requires these inside the container
		Privileged:   true,
		CgroupnsMode: "host",
		Tmpfs: map[string]string{
			"/run":      "",
			"/run/lock": "",
		},
		Binds: []string{"/sys/fs/cgroup:/sys/fs/cgroup:rw"},
	}
	if modCache != "" {
		// Share the host module cache read-only; configureGoProxy points Go at it.
		hostCfg.Binds = append(hostCfg.Binds, modCache+":"+containerModCacheDownload+":ro")
	}

	created, err := p.client.ContainerCreate(ctx, dockerclient.ContainerCreateOptions{
		Config: &container.Config{
			Image:    image,
			Hostname: name,
			// tag so cleanup can find leftovers not recorded in state
			Labels: map[string]string{containerLabel: ""},
		},
		HostConfig: hostCfg,
		Name:       name,
	})
	if err != nil {
		return common.Instance{}, fmt.Errorf("failed to create container: %w", err)
	}
	if _, err := p.client.ContainerStart(ctx, created.ID, dockerclient.ContainerStartOptions{}); err != nil {
		return common.Instance{}, fmt.Errorf("failed to start container: %w", err)
	}

	if err := p.installSSHKey(ctx, name, publicKey); err != nil {
		return common.Instance{}, err
	}

	if modCache != "" {
		p.configureGoProxy(ctx, name)
	}

	// The image runs a nested Docker daemon for tests that start helper containers
	// (kafka, logstash, ...). Wait for it to come up before handing back the instance
	// so those tests don't race a still-starting dockerd, and so a broken DinD setup
	// fails here with a clear message instead of deep inside a test.
	if err := p.waitForDockerd(ctx, name); err != nil {
		return common.Instance{}, err
	}

	ip, err := p.containerIP(ctx, name)
	if err != nil {
		return common.Instance{}, err
	}

	return common.Instance{
		ID:          batch.ID,
		Provisioner: Name,
		Name:        name,
		IP:          ip,
		Username:    sshUser,
		RemotePath:  fmt.Sprintf("/home/%s/agent", sshUser),
		// the image bakes in build-essential, unzip and the matching Go
		// toolchain, so the runner can skip its Prepare step entirely.
		Prepared: true,
	}, nil
}

// installSSHKey writes the runner's public key to the ssh user's authorized_keys.
// The key is piped via stdin to avoid any shell-quoting issues.
func (p *provisioner) installSSHKey(ctx context.Context, name string, publicKey []byte) error {
	script := fmt.Sprintf(
		"set -e; umask 077; mkdir -p /home/%[1]s/.ssh; cat >> /home/%[1]s/.ssh/authorized_keys; "+
			"chown -R %[1]s:%[1]s /home/%[1]s/.ssh", sshUser)
	stdin := bytes.NewReader(append(bytes.TrimSpace(publicKey), '\n'))
	if err := p.containerExec(ctx, name, stdin, "bash", "-c", script); err != nil {
		return fmt.Errorf("failed to install SSH key in container %s: %w", name, err)
	}
	return nil
}

// configureGoProxy points the ubuntu user's Go at the read-only host module cache
// mounted at containerModCacheDownload, falling back to the public proxy then direct
// for anything the host cache is missing. Writing it to the persistent `go env` file
// means it is honored by every later go invocation (including those mage shells out
// to), regardless of the SSH session's environment. Best-effort: a failure here only
// forfeits the download optimization, so it is logged rather than fatal.
func (p *provisioner) configureGoProxy(ctx context.Context, name string) {
	proxy := "file://" + containerModCacheDownload + ",https://proxy.golang.org,direct"
	script := "export HOME=/home/" + sshUser + "; go env -w GOPROXY=" + proxy
	if err := p.containerExec(ctx, name, nil, "su", sshUser, "-c", script); err != nil {
		p.logger.Logf("Configuring GOPROXY in container %s failed (continuing without the module cache): %s", name, err)
	}
}

// ensureImage builds the systemd image for the given Ubuntu version and baked-in
// tool versions if it does not already exist locally, returning the image reference.
// The Go/mage/gotestsum versions and a hash of the Dockerfile are part of the tag, so
// bumping any of them (e.g. via .go-version or go.mod) or editing the Dockerfile itself
// triggers a rebuild rather than reusing an image with stale baked contents.
func (p *provisioner) ensureImage(ctx context.Context, version string, bld imageBuild) (string, error) {
	dfHash := sha256.Sum256(dockerfile)
	image := fmt.Sprintf("%s:%s-go%s-mage%s-gts%s-df%s",
		imageRepo, version,
		strings.TrimPrefix(bld.goVersion, "v"),
		strings.TrimPrefix(bld.mageVersion, "v"),
		strings.TrimPrefix(bld.gotestsumVersion, "v"),
		hex.EncodeToString(dfHash[:])[:8])
	if _, err := p.client.ImageInspect(ctx, image); err == nil {
		return image, nil // already built
	}

	p.logger.Logf("Building docker image %s (first use; this can take a few minutes)", image)
	buildCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// The Dockerfile has no COPY/ADD so the build context is just the Dockerfile itself.
	buildContextTar, err := dockerfileTar(dockerfile)
	if err != nil {
		return "", fmt.Errorf("failed to create build context: %w", err)
	}

	goArch := runtime.GOARCH
	resp, err := p.client.ImageBuild(buildCtx, buildContextTar, dockerclient.ImageBuildOptions{
		Tags: []string{image},
		BuildArgs: map[string]*string{
			"UBUNTU_VERSION":    &version,
			"GO_VERSION":        &bld.goVersion,
			"GO_ARCH":           &goArch,
			"MAGE_VERSION":      &bld.mageVersion,
			"GOTESTSUM_VERSION": &bld.gotestsumVersion,
		},
		Remove: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to build image %s: %w", image, err)
	}
	defer resp.Body.Close()

	// Drain and decode the streaming build output; surface any build error.
	if err := decodeBuildOutput(resp.Body); err != nil {
		return "", fmt.Errorf("failed to build image %s: %w", image, err)
	}
	return image, nil
}

// dockerfileTar wraps a raw Dockerfile in a tar archive suitable for use as a
// Docker build context.
func dockerfileTar(df []byte) (io.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "Dockerfile", Mode: 0o644, Size: int64(len(df))}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(df); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}

// buildMessage is the subset of Docker's streaming build JSON we care about.
type buildMessage struct {
	Stream string `json:"stream"`
	Error  string `json:"error"`
}

// decodeBuildOutput reads the streaming JSON from an image build response body,
// returning a non-nil error if Docker reported a build failure.
func decodeBuildOutput(r io.Reader) error {
	dec := json.NewDecoder(r)
	for {
		var msg buildMessage
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

// waitForDockerd blocks until the nested Docker daemon inside the container responds
// to `docker info`, or the (bounded) context expires. systemd starts dockerd at boot,
// so it is usually ready by the time this runs, but the poll makes the dependency
// explicit and surfaces a daemon that never comes up (e.g. a storage-driver problem)
// as a clear provisioning error.
func (p *provisioner) waitForDockerd(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var lastErr error
	for {
		if err := p.containerExec(ctx, name, nil, "docker", "info"); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("nested docker daemon in container %s did not become ready: %w (last error: %w)",
				name, ctx.Err(), lastErr)
		case <-time.After(2 * time.Second):
		}
	}
}

func (p *provisioner) containerIP(ctx context.Context, name string) (string, error) {
	result, err := p.client.ContainerInspect(ctx, name, dockerclient.ContainerInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to inspect container %s: %w", name, err)
	}
	for _, ep := range result.Container.NetworkSettings.Networks {
		if ep.IPAddress.IsValid() {
			return ep.IPAddress.String(), nil
		}
	}
	return "", fmt.Errorf("container %s has no IP address", name)
}

func (p *provisioner) checkDocker(ctx context.Context) error {
	c, err := dockerclient.New(dockerclient.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	if _, err := c.ServerVersion(ctx, dockerclient.ServerVersionOptions{}); err != nil {
		return fmt.Errorf("docker does not appear to be running: %w", err)
	}
	p.client = c
	return nil
}

// containerExec runs cmd inside the named container, optionally piping stdin.
// It captures combined output and returns a non-nil error if the command exits
// non-zero, including the output in the error for diagnostics.
func (p *provisioner) containerExec(ctx context.Context, name string, stdin io.Reader, cmd ...string) error {
	opts := dockerclient.ExecCreateOptions{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          cmd,
	}
	if stdin != nil {
		opts.AttachStdin = true
	}

	execResp, err := p.client.ExecCreate(ctx, name, opts)
	if err != nil {
		return fmt.Errorf("exec create %v: %w", cmd, err)
	}

	attach, err := p.client.ExecAttach(ctx, execResp.ID, dockerclient.ExecAttachOptions{})
	if err != nil {
		return fmt.Errorf("exec attach %v: %w", cmd, err)
	}
	defer attach.Close()

	if stdin != nil {
		go func() {
			_, _ = io.Copy(attach.Conn, stdin)
			_ = attach.CloseWrite()
		}()
	}

	var out bytes.Buffer
	if err := demuxStream(&out, attach.Reader); err != nil {
		return fmt.Errorf("exec read %v: %w", cmd, err)
	}

	inspect, err := p.client.ExecInspect(ctx, execResp.ID, dockerclient.ExecInspectOptions{})
	if err != nil {
		return fmt.Errorf("exec inspect %v: %w", cmd, err)
	}
	if inspect.ExitCode != 0 {
		return fmt.Errorf("exec %v exited with code %d (output: %s)",
			cmd, inspect.ExitCode, strings.TrimSpace(out.String()))
	}
	return nil
}

// demuxStream reads Docker's multiplexed exec output (8-byte frame header followed
// by payload) and writes the combined stdout+stderr to dst. The frame format is:
// [stream-type (1 byte)][padding (3 bytes)][payload-size (4 bytes big-endian)].
func demuxStream(dst io.Writer, src io.Reader) error {
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(src, hdr); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		if _, err := io.CopyN(dst, src, n); err != nil {
			return err
		}
	}
}

// containerName derives a docker-safe container name from a batch ID.
func containerName(batchID string) string {
	mapped := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			return r
		default:
			return '-'
		}
	}, batchID)
	return containerNamePrefix + mapped
}
