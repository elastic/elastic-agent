// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package microshift

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/cenkalti/backoff/v5"

	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/kubernetes"
)

const (
	// Name is the INSTANCE_PROVISIONER value for MicroShift.
	Name = "microshift"

	imageArchivePath           = "/var/lib/microshift/elastic-agent-image.tar"
	microShiftKubeconfigPath   = "/var/lib/microshift/resources/kubeadmin/kubeconfig"
	microShiftKubeconfigServer = "https://localhost:6443"
	microShiftWaitTimeout      = 5 * time.Minute
)

var microShiftImagesByKubernetesMinor = map[string]string{
	"1.33": "ghcr.io/microshift-io/microshift:4.20.0_g153ff0ca9_4.20.0_okd_scos.16",
	"1.34": "ghcr.io/microshift-io/microshift:4.21.0_g29f429c21_4.21.0_okd_scos.ec.15",
	// TODO(samuelvl): microshift has not released a 4.22 image yet, use minc which is fully compatible.
	// Tracked in https://github.com/microshift-io/microshift/issues/235
	"1.35": "quay.io/minc-org/minc:4.22.0-okd-scos.ec.10",
}

// NewProvisioner creates a Kubernetes instance provisioner backed by MicroShift.
func NewProvisioner() common.InstanceProvisioner {
	return &provisioner{}
}

type provisioner struct {
	logger common.Logger
}

func (p *provisioner) Name() string {
	return Name
}

func (p *provisioner) Type() common.ProvisionerType {
	return common.ProvisionerTypeK8SCluster
}

func (p *provisioner) SetLogger(logger common.Logger) {
	p.logger = logger
}

func (p *provisioner) Supported(batch define.OS) bool {
	if batch.Type != define.Kubernetes || batch.Arch != runtime.GOARCH {
		return false
	}
	return batch.Distro == "" || batch.Distro == Name
}

func (p *provisioner) Provision(ctx context.Context, cfg common.Config, batches []common.OSBatch) ([]common.Instance, error) {
	var instances []common.Instance
	for _, batch := range batches {
		k8sVersion := fmt.Sprintf("v%s", batch.OS.Version)
		instanceName := fmt.Sprintf("%s-%s", k8sVersion, batch.Batch.Group)
		kubeConfig, containerName, err := p.setup(ctx, instanceName, k8sVersion)
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
			Internal: map[string]interface{}{
				"config":      kubeConfig,
				"version":     k8sVersion,
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

func (p *provisioner) setup(ctx context.Context, instanceName, k8sVersion string) (string, string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", "", fmt.Errorf("docker command missing: %w", err)
	}

	containerName := "microshift-" + instanceName
	microShiftImage, err := microShiftImageForKubernetesVersion(k8sVersion, runtime.GOARCH)
	if err != nil {
		return "", "", err
	}

	apiServerPort, adopted, err := p.existingContainerPort(ctx, containerName)
	if err != nil {
		return "", "", err
	}

	if adopted {
		p.logf("Reusing running MicroShift container %s on API port %d", containerName, apiServerPort)
	} else {
		apiServerPort, err = getFreePort()
		if err != nil {
			return "", "", fmt.Errorf("finding MicroShift API port: %w", err)
		}

		p.logf("MicroShift image: %s", microShiftImage)
		p.logf("MicroShift container: %s", containerName)
		p.logf("MicroShift API port: %d", apiServerPort)

		if err := p.run(ctx, "docker", "pull", microShiftImage); err != nil {
			return "", "", fmt.Errorf("pulling MicroShift image: %w", err)
		}
		runArgs := []string{
			"run",
			"--privileged",
			"--cgroupns=private",
			"--rm",
			"--detach",
			"--tty",
			"--name", containerName,
			"--hostname", "127.0.0.1.nip.io",
			"--publish", fmt.Sprintf("127.0.0.1:%d:6443", apiServerPort),
		}
		if microShiftIsMincImage(microShiftImage) {
			// minc needs a writable /host-container volume to start but it's never used
			runArgs = append(runArgs, "-v", "/host-container")
		}
		runArgs = append(runArgs, microShiftImage)
		if err := p.run(ctx, "docker", runArgs...); err != nil {
			return "", "", fmt.Errorf("starting MicroShift container: %w", err)
		}
	}

	_, err = backoff.Retry(
		ctx,
		func() (struct{}, error) {
			return struct{}{}, p.run(
				ctx,
				"docker",
				"exec",
				containerName,
				"/bin/test",
				"-f",
				microShiftKubeconfigPath,
			)
		},
		backoff.WithBackOff(backoff.NewConstantBackOff(1*time.Second)),
		backoff.WithMaxElapsedTime(microShiftWaitTimeout),
	)
	if err != nil {
		return "", "", errors.Join(
			fmt.Errorf("waiting for MicroShift kubeconfig: %w", err),
			p.diagnostics(context.Background(), containerName),
		)
	}

	kubeConfigContents, err := p.output(
		ctx,
		"docker",
		"exec",
		containerName,
		"/bin/cat",
		microShiftKubeconfigPath,
	)
	if err != nil {
		return "", "", errors.Join(
			fmt.Errorf("reading MicroShift kubeconfig: %w", err),
			p.diagnostics(context.Background(), containerName),
		)
	}
	if !strings.Contains(kubeConfigContents, microShiftKubeconfigServer) {
		return "", "", fmt.Errorf("MicroShift kubeconfig does not contain expected server %q", microShiftKubeconfigServer)
	}
	kubeConfigContents = strings.Replace(
		kubeConfigContents,
		microShiftKubeconfigServer,
		fmt.Sprintf("https://localhost:%d", apiServerPort),
		1,
	)
	kubeConfigFile, err := os.CreateTemp("", fmt.Sprintf("microshift-cluster-%s-kubecfg", instanceName))
	if err != nil {
		return "", "", fmt.Errorf("creating MicroShift kubeconfig file: %w", err)
	}
	kubeConfig := kubeConfigFile.Name()
	if _, err := kubeConfigFile.WriteString(kubeConfigContents); err != nil {
		_ = kubeConfigFile.Close()
		return "", "", fmt.Errorf("writing MicroShift kubeconfig: %w", err)
	}
	if err := kubeConfigFile.Close(); err != nil {
		return "", "", fmt.Errorf("closing MicroShift kubeconfig: %w", err)
	}
	p.logf("Kubeconfig: %s", kubeConfig)

	nodeReadyOutput, err := backoff.Retry(
		ctx,
		func() (string, error) {
			return p.output(
				ctx,
				"kubectl",
				"--kubeconfig", kubeConfig,
				"wait",
				"--for=condition=Ready",
				"nodes",
				"--all",
				"--timeout=10s",
			)
		},
		backoff.WithBackOff(backoff.NewConstantBackOff(1*time.Second)),
		backoff.WithMaxElapsedTime(microShiftWaitTimeout),
	)
	if err != nil {
		return "", "", errors.Join(
			fmt.Errorf("waiting for MicroShift node readiness: %w", err),
			p.diagnostics(context.Background(), containerName),
		)
	}
	p.logf("%s", strings.TrimSpace(nodeReadyOutput))

	return kubeConfig, containerName, nil
}

func (p *provisioner) existingContainerPort(ctx context.Context, containerName string) (uint16, bool, error) {
	running, err := p.output(ctx, "docker", "inspect", "-f", "{{.State.Running}}", containerName)
	if err != nil {
		return 0, false, nil //nolint:nilerr // inspect fails when no such container exists
	}

	if strings.TrimSpace(running) != "true" {
		return 0, false, fmt.Errorf("MicroShift container %s exists but is not running", containerName)
	}

	portOut, err := p.output(ctx, "docker", "port", containerName, "6443")
	if err != nil {
		return 0, false, fmt.Errorf("reading published port of MicroShift container %s: %w", containerName, err)
	}
	port, err := parsePublishedPort(portOut)
	if err != nil {
		return 0, false, fmt.Errorf("MicroShift container %s: %w", containerName, err)
	}
	return port, true, nil
}

func parsePublishedPort(portOut string) (uint16, error) {
	fields := strings.Fields(portOut)
	if len(fields) == 0 {
		return 0, fmt.Errorf("no published port in %q", portOut)
	}
	_, portStr, err := net.SplitHostPort(fields[0])
	if err != nil {
		return 0, fmt.Errorf("parsing published port %q: %w", fields[0], err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("parsing published port %q: %w", portStr, err)
	}
	return uint16(port), nil
}

func (p *provisioner) stopContainer(ctx context.Context, containerName string) error {
	if err := p.run(ctx, "docker", "stop", "--timeout", "0", containerName); err != nil {
		return fmt.Errorf("stopping MicroShift container %s: %w", containerName, err)
	}
	return nil
}

func (p *provisioner) diagnostics(ctx context.Context, containerName string) error {
	statusErr := p.run(
		ctx,
		"docker",
		"exec",
		containerName,
		"systemctl",
		"--no-pager",
		"--full",
		"status",
		"microshift.service",
	)
	if statusErr != nil {
		statusErr = fmt.Errorf("getting MicroShift service status: %w", statusErr)
	}
	journalErr := p.run(
		ctx,
		"docker",
		"exec",
		containerName,
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
	return errors.Join(statusErr, journalErr)
}

func (p *provisioner) loadImage(ctx context.Context, containerName, image string) error {
	saveCmd := exec.CommandContext(ctx, "docker", "image", "save", image)
	saveOutput, err := saveCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating Docker image stream: %w", err)
	}

	var saveError bytes.Buffer
	saveCmd.Stderr = &saveError
	writeCmd := exec.CommandContext(
		ctx,
		"docker",
		"exec",
		"--interactive",
		containerName,
		"sh",
		"-c",
		"cat > "+imageArchivePath,
	)
	writeCmd.Stdin = saveOutput
	var writeOutput bytes.Buffer
	writeCmd.Stdout = &writeOutput
	writeCmd.Stderr = &writeOutput

	if err := saveCmd.Start(); err != nil {
		return fmt.Errorf("starting Docker image save: %w", err)
	}
	if err := writeCmd.Run(); err != nil {
		_ = saveCmd.Process.Kill()
		_ = saveCmd.Wait()
		return fmt.Errorf("writing image archive in MicroShift container: %w: %s", err, strings.TrimSpace(writeOutput.String()))
	}
	if err := saveCmd.Wait(); err != nil {
		return fmt.Errorf("saving Docker image %s: %w: %s", image, err, strings.TrimSpace(saveError.String()))
	}

	defer func() {
		_ = p.run(context.Background(), "docker", "exec", containerName, "rm", "-f", imageArchivePath)
	}()

	return p.run(
		ctx,
		"docker",
		"exec",
		containerName,
		"skopeo",
		"copy",
		"docker-archive:"+imageArchivePath,
		"containers-storage:"+image,
	)
}

func (p *provisioner) run(ctx context.Context, name string, args ...string) error {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if len(output) > 0 {
		p.logf("%s", strings.TrimSpace(string(output)))
	}
	if err != nil {
		return fmt.Errorf(
			"%s %s failed: %w: %s",
			name,
			strings.Join(args, " "),
			err,
			strings.TrimSpace(string(output)),
		)
	}
	return nil
}

func (p *provisioner) output(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf(
			"%s %s failed: %w: %s",
			name,
			strings.Join(args, " "),
			err,
			strings.TrimSpace(stderr.String()),
		)
	}
	return string(output), nil
}

func (p *provisioner) logf(format string, args ...interface{}) {
	if p.logger != nil {
		p.logger.Logf(format, args...)
	}
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
	return uint16(listener.Addr().(*net.TCPAddr).Port), nil //nolint:gosec // G115 a TCP port is always within uint16 range
}

func microShiftImageForKubernetesVersion(kubernetesVersion, arch string) (string, error) {
	version, err := semver.NewVersion(kubernetesVersion)
	if err != nil {
		return "", fmt.Errorf("invalid Kubernetes version %q: %w", kubernetesVersion, err)
	}

	minor := fmt.Sprintf("%d.%d", version.Major(), version.Minor())
	image, found := microShiftImagesByKubernetesMinor[minor]
	if !found {
		return "", fmt.Errorf("no MicroShift image configured for Kubernetes version %q", kubernetesVersion)
	}
	if microShiftIsMincImage(image) {
		image = image + "-" + arch
	}
	return image, nil
}

func microShiftIsMincImage(image string) bool {
	return strings.HasPrefix(image, "quay.io/minc-org/minc:")
}
