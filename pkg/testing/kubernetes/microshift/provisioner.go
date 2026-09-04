// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package microshift

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	dockerclient "github.com/moby/moby/client"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"

	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/kubernetes"
)

const (
	// Name is the INSTANCE_PROVISIONER value for MicroShift provisioner.
	Name = "microshift"

	imageArchivePath           = "/var/lib/microshift/elastic-agent-image.tar"
	microShiftKubeconfigPath   = "/var/lib/microshift/resources/kubeadmin/kubeconfig"
	microShiftKubeconfigServer = "https://localhost:6443"
	microShiftWaitTimeout      = 5 * time.Minute
	microShiftStopTimeout      = 60 * time.Second
	microShiftCleanupTimeout   = 30 * time.Second
)

// microShiftAPIPort is the container port that serves the Kubernetes API.
var microShiftAPIPort = network.MustParsePort("6443/tcp")

var microShiftImagesByOpenShiftMinor = map[string]string{
	"4.20": "ghcr.io/microshift-io/microshift:4.20.0_g153ff0ca9_4.20.0_okd_scos.16",
	"4.21": "ghcr.io/microshift-io/microshift:4.21.0_g29f429c21_4.21.0_okd_scos.ec.15",
	// TODO(samuelvl): microshift has not released a 4.22 image yet, use minc which is fully compatible.
	// Tracked in https://github.com/microshift-io/microshift/issues/235
	"4.22": "quay.io/minc-org/minc:4.22.0-okd-scos.ec.10",
}

// NewProvisioner creates a Kubernetes instance provisioner backed by MicroShift.
func NewProvisioner(ctx context.Context) (common.InstanceProvisioner, error) {
	client, err := kubernetes.NewDockerClient()
	if err != nil {
		return nil, fmt.Errorf("creating Docker client: %w", err)
	}
	if _, err := client.ServerVersion(ctx, dockerclient.ServerVersionOptions{}); err != nil {
		return nil, fmt.Errorf("docker does not appear to be running: %w", err)
	}
	return &provisioner{client: client}, nil
}

type provisioner struct {
	logger common.Logger
	client *dockerclient.Client
}

func (p *provisioner) Name() string {
	return Name
}

func (p *provisioner) Type() common.ProvisionerType {
	return common.ProvisionerTypeK8SCluster
}

func (p *provisioner) Location() common.ProvisionerLocation {
	return common.ProvisionerLocationLocal
}

func (p *provisioner) SetLogger(l common.Logger) {
	p.logger = l
}

func (p *provisioner) Supported(batch define.OS) bool {
	if batch.Type != define.Kubernetes || batch.Arch != runtime.GOARCH {
		return false
	}
	if batch.Distro != "" && batch.Distro != kubernetes.OpenShiftDistro {
		// not openshift, don't run
		return false
	}
	return true
}

func (p *provisioner) Provision(ctx context.Context, cfg common.Config, batches []common.OSBatch) ([]common.Instance, error) {
	var instances []common.Instance
	for _, batch := range batches {
		openshiftVersion := batch.OS.Version
		instanceName := fmt.Sprintf("%s-%s", openshiftVersion, batch.Batch.Group)
		kubeConfig, containerName, err := p.setup(ctx, instanceName, openshiftVersion)
		if err != nil {
			return nil, err
		}

		agentImageName, err := kubernetes.VariantToImage(batch.OS.DockerVariant)
		if err != nil {
			return nil, err
		}
		agentImageName = fmt.Sprintf("%s:%s", agentImageName, cfg.AgentVersion)
		agentImage, err := kubernetes.AddK8STestsToImage(ctx, p.logger, agentImageName, runtime.GOARCH)
		if err != nil {
			return nil, fmt.Errorf("failed to add Kubernetes tests to image %s: %w", agentImageName, err)
		}
		if err := p.loadImage(ctx, containerName, agentImage); err != nil {
			return nil, err
		}

		instances = append(instances, common.Instance{
			ID:          batch.ID,
			Name:        instanceName,
			Provisioner: Name,
			Internal: map[string]any{
				"config":      kubeConfig,
				"version":     openshiftVersion,
				"agent_image": agentImage,
				"container":   containerName,
			},
		})
	}
	return instances, nil
}

func (p *provisioner) Clean(ctx context.Context, _ common.Config, instances []common.Instance) error {
	var errs []error
	for _, instance := range instances {
		containerName, _ := instance.Internal["container"].(string)
		if containerName == "" {
			containerName = "microshift-" + instance.Name
		}

		if err := p.stopContainer(ctx, containerName); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *provisioner) setup(ctx context.Context, instanceName, openshiftVersion string) (_ string, _ string, err error) {
	containerName := "microshift-" + instanceName
	microShiftImage, err := microShiftImageForOpenShiftVersion(openshiftVersion, runtime.GOARCH)
	if err != nil {
		return "", "", err
	}

	apiServerPort, exists, err := p.getMicroShiftAPIPort(ctx, containerName)
	if err != nil {
		return "", "", err
	}

	if exists {
		p.logger.Logf("Reusing running MicroShift container %s on API port %d", containerName, apiServerPort)
	} else {
		apiServerPort, err = getFreePort()
		if err != nil {
			return "", "", fmt.Errorf("finding MicroShift API port: %w", err)
		}

		p.logger.Logf("MicroShift image: %s", microShiftImage)
		p.logger.Logf("MicroShift container: %s", containerName)
		p.logger.Logf("MicroShift API port: %d", apiServerPort)

		pullStart := time.Now()
		if err := p.pullImage(ctx, microShiftImage); err != nil {
			return "", "", err
		}
		p.logger.Logf("MicroShift image pulled in %s", time.Since(pullStart).Round(time.Millisecond))

		if err := p.startContainer(ctx, containerName, microShiftImage, apiServerPort); err != nil {
			return "", "", err
		}
	}

	defer func() {
		if err != nil {
			diagCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), microShiftCleanupTimeout)
			defer cancel()
			diagnostics, diagErr := p.collectDiagnostics(diagCtx, containerName)
			if diagnostics != "" {
				p.logger.Logf("MicroShift diagnostics:\n%s", diagnostics)
			}
			err = errors.Join(err, diagErr)
		}
	}()

	kubeConfig, err := p.writeKubeconfig(ctx, instanceName, containerName, apiServerPort)
	if err != nil {
		return "", "", err
	}
	p.logger.Logf("MicroShift kubeconfig written to %s", kubeConfig)

	k8sClient, err := klient.NewWithKubeConfigFile(kubeConfig)
	if err != nil {
		return "", "", fmt.Errorf("building Kubernetes client from %s: %w", kubeConfig, err)
	}
	if err := p.waitForNodesReady(ctx, k8sClient); err != nil {
		return "", "", fmt.Errorf("waiting for MicroShift node readiness: %w", err)
	}

	return kubeConfig, containerName, nil
}

func (p *provisioner) writeKubeconfig(ctx context.Context, instanceName, containerName string, apiServerPort uint16) (string, error) {
	waitStart := time.Now()
	var kubeConfigErr error
	err := wait.For(
		func(ctx context.Context) (bool, error) {
			_, kubeConfigErr = p.containerExecOutput(ctx, containerName, nil, "/bin/test", "-f", microShiftKubeconfigPath)
			return kubeConfigErr == nil, nil
		},
		wait.WithContext(ctx),
		wait.WithTimeout(microShiftWaitTimeout),
		wait.WithInterval(time.Second),
	)
	if err != nil {
		return "", errors.Join(fmt.Errorf("waiting for MicroShift kubeconfig: %w", err), kubeConfigErr)
	}
	p.logger.Logf("MicroShift kubeconfig available in %s", time.Since(waitStart).Round(time.Millisecond))

	contents, err := p.containerExecOutput(ctx, containerName, nil, "/bin/cat", microShiftKubeconfigPath)
	if err != nil {
		return "", fmt.Errorf("reading MicroShift kubeconfig: %w", err)
	}
	if !strings.Contains(contents, microShiftKubeconfigServer) {
		return "", fmt.Errorf("MicroShift kubeconfig does not contain expected server %q", microShiftKubeconfigServer)
	}
	contents = strings.Replace(
		contents,
		microShiftKubeconfigServer,
		fmt.Sprintf("https://localhost:%d", apiServerPort),
		1,
	)

	file, err := os.CreateTemp("", fmt.Sprintf("microshift-cluster-%s-kubecfg", instanceName))
	if err != nil {
		return "", fmt.Errorf("creating MicroShift kubeconfig file: %w", err)
	}
	if _, err := file.WriteString(contents); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("writing MicroShift kubeconfig: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("closing MicroShift kubeconfig: %w", err)
	}
	return file.Name(), nil
}

func (p *provisioner) waitForNodesReady(ctx context.Context, client klient.Client) error {
	res, err := resources.New(client.RESTConfig())
	if err != nil {
		return fmt.Errorf("building Kubernetes resource client: %w", err)
	}

	waitStart := time.Now()
	var nodesReady []string
	var nodeErr error
	err = wait.For(
		func(ctx context.Context) (bool, error) {
			var nodes corev1.NodeList
			if nodeErr = res.List(ctx, &nodes); nodeErr != nil {
				return false, nil //nolint:nilerr // the API server refuses connections until it is up, so keep polling
			}
			if len(nodes.Items) == 0 {
				nodeErr = errors.New("cluster reports no nodes")
				return false, nil
			}
			nodesReady = nodesReady[:0]
			for _, node := range nodes.Items {
				if !isNodeReady(node) {
					nodeErr = fmt.Errorf("node %s is not ready", node.Name)
					return false, nil
				}
				nodesReady = append(nodesReady, node.Name)
			}
			return true, nil
		},
		wait.WithContext(ctx),
		wait.WithTimeout(microShiftWaitTimeout),
		wait.WithInterval(time.Second),
	)
	if err != nil {
		return errors.Join(err, nodeErr)
	}
	p.logger.Logf(
		"MicroShift nodes ready in %s: %s",
		time.Since(waitStart).Round(time.Millisecond),
		strings.Join(nodesReady, ", "),
	)
	return nil
}

func isNodeReady(node corev1.Node) bool {
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

func (p *provisioner) containerExecOutput(ctx context.Context, name string, stdin io.Reader, cmd ...string) (string, error) {
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
		return "", fmt.Errorf("exec create %v: %w", cmd, err)
	}

	attach, err := p.client.ExecAttach(ctx, execResp.ID, dockerclient.ExecAttachOptions{})
	if err != nil {
		return "", fmt.Errorf("exec attach %v: %w", cmd, err)
	}
	defer attach.Close()

	if stdin != nil {
		go func() {
			_, _ = io.Copy(attach.Conn, stdin)
			_ = attach.CloseWrite()
		}()
	}

	var stdout, stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(&stdout, &stderr, attach.Reader); err != nil {
		return "", fmt.Errorf("exec read %v: %w", cmd, err)
	}

	inspect, err := p.client.ExecInspect(ctx, execResp.ID, dockerclient.ExecInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("exec inspect %v: %w", cmd, err)
	}
	if inspect.ExitCode != 0 {
		return stdout.String(), fmt.Errorf("exec %v exited with code %d (output: %s)",
			cmd, inspect.ExitCode, strings.TrimSpace(stdout.String()+stderr.String()))
	}
	return stdout.String(), nil
}

func (p *provisioner) getMicroShiftAPIPort(ctx context.Context, containerName string) (uint16, bool, error) {
	result, err := p.client.ContainerInspect(ctx, containerName, dockerclient.ContainerInspectOptions{})
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("inspecting MicroShift container %s: %w", containerName, err)
	}

	if result.Container.State == nil || !result.Container.State.Running {
		return 0, false, fmt.Errorf("MicroShift container %s exists but is not running", containerName)
	}

	bindings := result.Container.NetworkSettings.Ports[microShiftAPIPort]
	if len(bindings) == 0 {
		return 0, false, fmt.Errorf("MicroShift container %s publishes no port for %s", containerName, microShiftAPIPort)
	}
	port, err := strconv.ParseUint(bindings[0].HostPort, 10, 16)
	if err != nil {
		return 0, false, fmt.Errorf(
			"MicroShift container %s: parsing published port %q: %w",
			containerName, bindings[0].HostPort, err,
		)
	}
	return uint16(port), true, nil
}

func (p *provisioner) collectDiagnostics(ctx context.Context, containerName string) (string, error) {
	status, statusErr := p.containerExecOutput(
		ctx,
		containerName,
		nil,
		"systemctl",
		"--no-pager",
		"--full",
		"status",
		"microshift.service",
	)
	if statusErr != nil {
		statusErr = fmt.Errorf("getting MicroShift service status: %w", statusErr)
	}
	journal, journalErr := p.containerExecOutput(
		ctx,
		containerName,
		nil,
		"journalctl",
		"--no-pager",
		"--unit",
		"microshift.service",
		"--lines",
		"200",
	)
	if journalErr != nil {
		journalErr = fmt.Errorf("getting MicroShift service journal: %w", journalErr)
	}

	output := strings.TrimSpace(status) + "\n" + strings.TrimSpace(journal)
	return output, errors.Join(statusErr, journalErr)
}

func (p *provisioner) loadImage(ctx context.Context, containerName, image string) error {
	archive, err := p.client.ImageSave(ctx, []string{image})
	if err != nil {
		return fmt.Errorf("saving Docker image %s: %w", image, err)
	}
	defer archive.Close()

	if _, err := p.containerExecOutput(ctx, containerName, archive, "sh", "-c", "cat > "+imageArchivePath); err != nil {
		return fmt.Errorf("writing image archive in MicroShift container: %w", err)
	}

	defer func() {
		rmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), microShiftCleanupTimeout)
		defer cancel()
		if _, err := p.containerExecOutput(rmCtx, containerName, nil, "rm", "-f", imageArchivePath); err != nil {
			p.logger.Logf("Removing image archive %s failed: %s", imageArchivePath, err)
		}
	}()

	_, err = p.containerExecOutput(
		ctx,
		containerName,
		nil,
		"skopeo",
		"copy",
		"docker-archive:"+imageArchivePath,
		"containers-storage:"+image,
	)
	return err
}

func (p *provisioner) pullImage(ctx context.Context, image string) error {
	resp, err := p.client.ImagePull(ctx, image, dockerclient.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pulling MicroShift image %s: %w", image, err)
	}
	defer resp.Close()

	if err := resp.Wait(ctx); err != nil {
		return fmt.Errorf("pulling MicroShift image %s: %w", image, err)
	}
	return nil
}

func (p *provisioner) startContainer(ctx context.Context, containerName, image string, apiServerPort uint16) error {
	cfg := &container.Config{
		Image:        image,
		Hostname:     "127.0.0.1.nip.io",
		Tty:          true,
		ExposedPorts: network.PortSet{microShiftAPIPort: struct{}{}},
	}

	// minc needs a writable /host-container volume to start but it's never used
	if microShiftIsMincImage(image) {
		cfg.Volumes = map[string]struct{}{"/host-container": {}}
	}

	hostCfg := &container.HostConfig{
		Privileged:   true,
		CgroupnsMode: container.CgroupnsModePrivate,
		AutoRemove:   true,
		PortBindings: network.PortMap{
			microShiftAPIPort: []network.PortBinding{{
				HostIP:   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
				HostPort: strconv.FormatUint(uint64(apiServerPort), 10),
			}},
		},
	}

	created, err := p.client.ContainerCreate(ctx, dockerclient.ContainerCreateOptions{
		Config:     cfg,
		HostConfig: hostCfg,
		Name:       containerName,
	})
	if err != nil {
		return fmt.Errorf("creating MicroShift container %s: %w", containerName, err)
	}
	for _, warning := range created.Warnings {
		p.logger.Logf("MicroShift container %s: %s", containerName, warning)
	}

	if _, err := p.client.ContainerStart(ctx, created.ID, dockerclient.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("starting MicroShift container %s: %w", containerName, err)
	}
	return nil
}

func (p *provisioner) stopContainer(ctx context.Context, containerName string) error {
	opts := dockerclient.ContainerStopOptions{
		Timeout: new(int(microShiftStopTimeout.Seconds())),
	}
	_, err := p.client.ContainerStop(ctx, containerName, opts)
	if err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("stopping MicroShift container %s: %w", containerName, err)
	}
	return nil
}

func getFreePort() (uint16, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected listener address type %T", listener.Addr())
	}
	return uint16(tcpAddr.Port), nil //nolint:gosec // G115 a TCP port is always within uint16 range
}

func microShiftImageForOpenShiftVersion(openshiftVersion, arch string) (string, error) {
	version, err := semver.NewVersion(openshiftVersion)
	if err != nil {
		return "", fmt.Errorf("invalid OpenShift version %q: %w", openshiftVersion, err)
	}

	minor := fmt.Sprintf("%d.%d", version.Major(), version.Minor())
	image, found := microShiftImagesByOpenShiftMinor[minor]
	if !found {
		return "", fmt.Errorf("no MicroShift image configured for OpenShift version %q", openshiftVersion)
	}
	if microShiftIsMincImage(image) {
		image = image + "-" + arch
	}
	return image, nil
}

func microShiftIsMincImage(image string) bool {
	return strings.HasPrefix(image, "quay.io/minc-org/minc:")
}
