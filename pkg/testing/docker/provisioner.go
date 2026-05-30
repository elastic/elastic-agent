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
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

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
		// -v also drops the anonymous /var/lib/docker volume backing the nested daemon
		if _, err := p.docker(ctx, nil, "rm", "-fv", instance.Name); err != nil {
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
	for _, filter := range []string{"label=" + containerLabel, "name=" + containerNamePrefix} {
		out, err := p.docker(ctx, nil, "ps", "-aq", "--filter", filter)
		if err != nil {
			p.logger.Logf("Listing leftover %s containers (%s) failed: %s", Name, filter, err)
			continue
		}
		for _, id := range strings.Fields(out) {
			leftovers[id] = struct{}{}
		}
	}
	for id := range leftovers {
		if _, err := p.docker(ctx, nil, "rm", "-fv", id); err != nil {
			p.logger.Logf("Delete leftover container %s failed: %s", id, err)
		}
	}
	return nil
}

// AttachInstanceToNetwork connects the instance's container to an additional docker
// network so it can reach a stack running on that network (see
// common.InstanceNetworkAttacher). It is idempotent: re-attaching an
// already-connected container is treated as success.
func (p *provisioner) AttachInstanceToNetwork(ctx context.Context, instance common.Instance, network string) error {
	out, err := p.docker(ctx, nil, "network", "connect", network, instance.Name)
	if err != nil {
		if strings.Contains(out, "already exists in network") || strings.Contains(out, "already connected") {
			return nil
		}
		return fmt.Errorf("failed to connect container %s to network %s: %w", instance.Name, network, err)
	}
	return nil
}

// launch creates (or recreates) the container for a batch and returns its instance.
// modCache, when non-empty, is the host Go module download cache to share read-only.
func (p *provisioner) launch(ctx context.Context, batch common.OSBatch, build imageBuild, publicKey []byte, modCache string) (common.Instance, error) {
	name := containerName(batch.ID)
	version := batch.OS.Version
	if version == "" {
		version = "24.04"
	}

	image, err := p.ensureImage(ctx, version, build)
	if err != nil {
		return common.Instance{}, err
	}

	// remove any pre-existing container with the same name so the run is fresh
	// (-v also clears its old /var/lib/docker volume)
	_, _ = p.docker(ctx, nil, "rm", "-fv", name)

	p.logger.Logf("Starting container %s (%s)", name, image)
	runArgs := []string{
		"run", "-d",
		"--name", name,
		"--hostname", name,
		// tag so cleanup can find leftovers not recorded in state
		"--label", containerLabel,
		// systemd as PID 1 requires these inside the container
		"--privileged",
		"--cgroupns=host",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
		"--tmpfs", "/run",
		"--tmpfs", "/run/lock",
	}
	if modCache != "" {
		// Share the host module cache read-only; configureGoProxy points Go at it.
		runArgs = append(runArgs, "-v", modCache+":"+containerModCacheDownload+":ro")
	}
	runArgs = append(runArgs, image)
	if _, err := p.docker(ctx, nil, runArgs...); err != nil {
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
	if _, err := p.docker(ctx, stdin, "exec", "-i", name, "bash", "-c", script); err != nil {
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
	if _, err := p.docker(ctx, nil, "exec", name, "su", sshUser, "-c", script); err != nil {
		p.logger.Logf("Configuring GOPROXY in container %s failed (continuing without the module cache): %s", name, err)
	}
}

// ensureImage builds the systemd image for the given Ubuntu version and baked-in
// tool versions if it does not already exist locally, returning the image reference.
// The Go/mage/gotestsum versions and a hash of the Dockerfile are part of the tag, so
// bumping any of them (e.g. via .go-version or go.mod) or editing the Dockerfile itself
// triggers a rebuild rather than reusing an image with stale baked contents.
func (p *provisioner) ensureImage(ctx context.Context, version string, build imageBuild) (string, error) {
	dfHash := sha256.Sum256(dockerfile)
	image := fmt.Sprintf("%s:%s-go%s-mage%s-gts%s-df%s",
		imageRepo, version,
		strings.TrimPrefix(build.goVersion, "v"),
		strings.TrimPrefix(build.mageVersion, "v"),
		strings.TrimPrefix(build.gotestsumVersion, "v"),
		hex.EncodeToString(dfHash[:])[:8])
	if _, err := p.docker(ctx, nil, "image", "inspect", image); err == nil {
		return image, nil // already built
	}

	p.logger.Logf("Building docker image %s (first use; this can take a few minutes)", image)
	buildCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	// Feed the Dockerfile on stdin; it has no COPY/ADD so it needs no build context.
	if _, err := p.docker(buildCtx, bytes.NewReader(dockerfile),
		"build", "-t", image,
		"--build-arg", "UBUNTU_VERSION="+version,
		"--build-arg", "GO_VERSION="+build.goVersion,
		"--build-arg", "GO_ARCH="+runtime.GOARCH,
		"--build-arg", "MAGE_VERSION="+build.mageVersion,
		"--build-arg", "GOTESTSUM_VERSION="+build.gotestsumVersion,
		"-"); err != nil {
		return "", fmt.Errorf("failed to build image %s: %w", image, err)
	}
	return image, nil
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
		if _, err := p.docker(ctx, nil, "exec", name, "docker", "info"); err == nil {
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
	out, err := p.docker(ctx, nil, "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(out)
	if ip == "" {
		return "", fmt.Errorf("container %s has no IP address", name)
	}
	return ip, nil
}

func (p *provisioner) checkDocker(ctx context.Context) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found in PATH: %w", err)
	}
	if _, err := p.docker(ctx, nil, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("docker does not appear to be running: %w", err)
	}
	return nil
}

// docker runs the docker CLI, returning its combined output.
func (p *provisioner) docker(ctx context.Context, stdin io.Reader, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("docker %s failed: %w (output: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
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
