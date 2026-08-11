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
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
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

		provisioned := false
		defer func() {
			if !provisioned && !microShiftSkipDelete() {
				_ = p.stopContainer(context.Background(), containerName)
			}
		}()

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
		provisioned = true
	}
	return instances, nil
}

func (p *provisioner) Clean(ctx context.Context, _ common.Config, instances []common.Instance) error {
	if microShiftSkipDelete() {
		return nil
	}

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
	apiServerPort, err := getFreePort()
	if err != nil {
		return "", "", fmt.Errorf("finding MicroShift API port: %w", err)
	}
	microShiftImage, err := microShiftImageForKubernetesVersion(k8sVersion)
	if err != nil {
		return "", "", err
	}

	p.logf("MicroShift image: %s", microShiftImage)
	p.logf("MicroShift container: %s", containerName)
	p.logf("MicroShift API port: %d", apiServerPort)

	if err := p.run(ctx, "docker", "pull", microShiftImage); err != nil {
		return "", "", fmt.Errorf("pulling MicroShift image: %w", err)
	}
	if err := p.run(
		ctx,
		"docker",
		"run",
		"--privileged",
		"--cgroupns=private",
		"--rm",
		"--detach",
		"--tty",
		"--name", containerName,
		"--hostname", "127.0.0.1.nip.io",
		"--publish", fmt.Sprintf("127.0.0.1:%d:6443", apiServerPort),
		microShiftImage,
	); err != nil {
		return "", "", fmt.Errorf("starting MicroShift container: %w", err)
	}

	setupComplete := false
	defer func() {
		if !setupComplete {
			_ = p.stopContainer(context.Background(), containerName)
		}
	}()

	deadline := time.Now().Add(microShiftWaitTimeout)
	for {
		if err := p.run(
			ctx,
			"docker",
			"exec",
			containerName,
			"/bin/test",
			"-f",
			microShiftKubeconfigPath,
		); err == nil {
			break
		}
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		if time.Now().After(deadline) {
			return "", "", errors.Join(
				fmt.Errorf("timed out waiting for MicroShift kubeconfig after %s", microShiftWaitTimeout),
				p.diagnostics(context.Background(), containerName),
			)
		}
		if err := wait(ctx, time.Second); err != nil {
			return "", "", err
		}
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

	deadline = time.Now().Add(microShiftWaitTimeout)
	for {
		err = p.run(
			ctx,
			"kubectl",
			"--kubeconfig", kubeConfig,
			"wait",
			"--for=condition=Ready",
			"nodes",
			"--all",
			"--timeout=10s",
		)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		if time.Now().After(deadline) {
			return "", "", errors.Join(
				fmt.Errorf("timed out waiting for MicroShift node readiness after %s: %w", microShiftWaitTimeout, err),
				p.diagnostics(context.Background(), containerName),
			)
		}
		if err := wait(ctx, time.Second); err != nil {
			return "", "", err
		}
	}

	setupComplete = true
	return kubeConfig, containerName, nil
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
	return uint16(listener.Addr().(*net.TCPAddr).Port), nil
}

func microShiftSkipDelete() bool {
	return os.Getenv("MICROSHIFT_SKIP_DELETE") == "true"
}

func microShiftImageForKubernetesVersion(kubernetesVersion string) (string, error) {
	version, err := semver.NewVersion(kubernetesVersion)
	if err != nil {
		return "", fmt.Errorf("invalid Kubernetes version %q: %w", kubernetesVersion, err)
	}

	minor := fmt.Sprintf("%d.%d", version.Major(), version.Minor())
	image, found := microShiftImagesByKubernetesMinor[minor]
	if !found {
		return "", fmt.Errorf("no MicroShift image configured for Kubernetes version %q", kubernetesVersion)
	}
	return image, nil
}

func wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
