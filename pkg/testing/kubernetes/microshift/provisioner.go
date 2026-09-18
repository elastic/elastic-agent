// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package microshift

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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
	configv1 "github.com/openshift/api/config/v1"
	v1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"

	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/kubernetes"
)

// Name is the INSTANCE_PROVISIONER value for the MicroShift provisioner.
const Name = "microshift"

const (
	agentImageArchivePath = "/var/lib/microshift/elastic-agent-image.tar"
	kubeconfigPath        = "/var/lib/microshift/resources/kubeadmin/kubeconfig"
	kubeconfigServer      = "https://localhost:6443"
)

const (
	writeKubeconfigTimeout  = 5 * time.Minute
	controlPlaneTimeout     = 2 * time.Minute
	crdCreationTimeout      = 1 * time.Minute
	containerStopTimeout    = 1 * time.Minute
	loadImageCleanupTimeout = 30 * time.Second
)

// apiPort is the container port that serves the Kubernetes API.
var apiPort = network.MustParsePort("6443/tcp")

var imagesByKubernetesMinor = map[string]string{
	"1.33": "ghcr.io/microshift-io/microshift:4.20.0_g153ff0ca9_4.20.0_okd_scos.16",
	"1.34": "ghcr.io/microshift-io/microshift:4.21.0_g29f429c21_4.21.0_okd_scos.ec.15",
	// TODO(samuelvl): microshift has not released a 4.22 image yet, use minc which is fully compatible.
	// Tracked in https://github.com/microshift-io/microshift/issues/235
	"1.35": "quay.io/minc-org/minc:4.22.0-okd-scos.ec.10",
}

var openShiftCRDManifestPaths = []string{
	"pkg/testing/kubernetes/microshift/manifests/infrastructure-crds.yaml",
	"pkg/testing/kubernetes/microshift/manifests/monitoring-crds.yaml",
}

// NewProvisioner creates a Kubernetes instance provisioner backed by MicroShift.
func NewProvisioner() (common.InstanceProvisioner, error) {
	client, err := kubernetes.NewDockerClient()
	if err != nil {
		return nil, fmt.Errorf("creating Docker client: %w", err)
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
	if batch.Distro != "" && batch.Distro != kubernetes.KubernetesDistro {
		// not kubernetes, don't run
		return false
	}
	return true
}

func (p *provisioner) Provision(ctx context.Context, cfg common.Config, batches []common.OSBatch) ([]common.Instance, error) {
	var instances []common.Instance
	for _, batch := range batches {
		k8sVersion := batch.OS.Version
		instanceName := fmt.Sprintf("%s-%s", k8sVersion, batch.Batch.Group)

		agentImage, err := kubernetes.FindVariantImage(ctx, p.client, batch.OS.DockerVariant, cfg.AgentVersion, runtime.GOARCH)
		if err != nil {
			return nil, err
		}

		testsImage, err := kubernetes.BuildInnerTestsImage(ctx, p.logger, p.client, agentImage, runtime.GOARCH)
		if err != nil {
			return nil, fmt.Errorf("building inner tests image from %s: %w", agentImage, err)
		}

		kConfigPath, containerName, err := p.setup(ctx, instanceName, k8sVersion, cfg.RepoDir)
		if err != nil {
			return nil, err
		}

		loadImageStart := time.Now()
		if err := p.loadImage(ctx, containerName, testsImage); err != nil {
			return nil, err
		}
		p.logger.Logf("microshift: agent image loaded in %s", time.Since(loadImageStart).Round(time.Millisecond))

		instances = append(instances, common.Instance{
			ID:          batch.ID,
			Name:        instanceName,
			Provisioner: Name,
			Internal: map[string]any{
				"config":      kConfigPath,
				"version":     k8sVersion,
				"agent_image": testsImage,
				"container":   containerName,
			},
		})
	}
	return instances, nil
}

func (p *provisioner) setup(ctx context.Context, instanceName, kubernetesVersion, repoDir string) (string, string, error) {
	containerName := fmt.Sprintf("%s-%s", Name, instanceName)
	microShiftImage, err := microShiftImageForKubernetesVersion(kubernetesVersion, runtime.GOARCH)
	if err != nil {
		return "", "", err
	}

	apiServerPort, exists, err := p.getMicroShiftAPIPort(ctx, containerName)
	if err != nil {
		return "", "", err
	}

	if exists {
		p.logger.Logf("microshift: reusing running container %s on API port %d", containerName, apiServerPort)
	} else {
		apiServerPort, err = getFreePort()
		if err != nil {
			return "", "", fmt.Errorf("finding MicroShift API port: %w", err)
		}

		pullStart := time.Now()
		if err := p.pullImage(ctx, microShiftImage); err != nil {
			return "", "", err
		}
		p.logger.Logf("microshift: image pulled in %s", time.Since(pullStart).Round(time.Millisecond))

		if err := p.startContainer(ctx, containerName, microShiftImage, apiServerPort); err != nil {
			return "", "", err
		}
	}

	controlPlaneStart := time.Now()
	kubeConfig, err := p.writeKubeconfig(ctx, instanceName, containerName, apiServerPort)
	if err != nil {
		return "", "", err
	}
	p.logger.Logf("microshift: kubeconfig written to %s", kubeConfig)

	c, err := klient.NewWithKubeConfigFile(kubeConfig)
	if err != nil {
		return "", "", fmt.Errorf("building Kubernetes client from %s: %w", kubeConfig, err)
	}
	if err := p.waitForControlPlane(ctx, c); err != nil {
		return "", "", fmt.Errorf("waiting for MicroShift control plane: %w", err)
	}
	p.logger.Logf("microshift: control plane ready in %s", time.Since(controlPlaneStart).Round(time.Millisecond))

	if !exists {
		// MicroShift does not provide the OpenShift monitoring andinfrastructure CRDs
		// available in full OpenShift clusters.
		if err := p.installOpenShiftCRDs(ctx, c, repoDir); err != nil {
			return "", "", fmt.Errorf("installing OpenShift CRDs: %w", err)
		}
		// MicroShift does not create the Infrastructure/cluster object that identifies
		// an OpenShift cluster, used by otel_helm_test.go tests.
		if err := p.createInfrastructureObject(ctx, c, instanceName); err != nil {
			return "", "", fmt.Errorf("creating Infrastructure object: %w", err)
		}
	}
	p.logger.Logf("microshift: cluster %s is ready", instanceName)

	return kubeConfig, containerName, nil
}

func (p *provisioner) loadImage(ctx context.Context, containerName, image string) error {
	archive, err := p.client.ImageSave(ctx, []string{image})
	if err != nil {
		return fmt.Errorf("saving Docker image %s: %w", image, err)
	}
	defer archive.Close()

	if _, err := p.containerExecOutput(ctx, containerName, archive, "sh", "-c", "cat > "+agentImageArchivePath); err != nil {
		return fmt.Errorf("writing image archive in MicroShift container: %w", err)
	}

	defer func() {
		rmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), loadImageCleanupTimeout)
		defer cancel()
		if _, err := p.containerExecOutput(rmCtx, containerName, nil, "rm", "-f", agentImageArchivePath); err != nil {
			p.logger.Logf("microshift: removing image archive %s failed: %s", agentImageArchivePath, err)
		}
	}()

	_, err = p.containerExecOutput(
		ctx,
		containerName,
		nil,
		"skopeo",
		"copy",
		"docker-archive:"+agentImageArchivePath,
		"containers-storage:"+image,
	)
	return err
}

func (p *provisioner) waitForControlPlane(ctx context.Context, client klient.Client) error {
	r := client.Resources()
	for _, sl := range []metav1.LabelSelectorRequirement{
		{Key: "k8s-app", Operator: metav1.LabelSelectorOpIn, Values: []string{"kindnet", "kube-proxy"}},
		{Key: "dns.operator.openshift.io/daemonset-dns", Operator: metav1.LabelSelectorOpIn, Values: []string{"default"}},
	} {
		selector, err := metav1.LabelSelectorAsSelector(
			&metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					sl,
				},
			},
		)
		if err != nil {
			return err
		}
		err = wait.For(conditions.New(r).ResourceListMatchN(&v1.PodList{}, len(sl.Values), func(object k8s.Object) bool {
			pod, ok := object.(*v1.Pod)
			if !ok {
				return false
			}

			for _, cond := range pod.Status.Conditions {
				if cond.Type != v1.PodReady {
					continue
				}

				return cond.Status == v1.ConditionTrue
			}

			return false
		}, resources.WithLabelSelector(selector.String())), wait.WithContext(ctx), wait.WithTimeout(controlPlaneTimeout))
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *provisioner) installOpenShiftCRDs(ctx context.Context, client klient.Client, repoDir string) error {
	r := client.Resources()
	if err := apiextensionsv1.AddToScheme(r.GetScheme()); err != nil {
		return fmt.Errorf("registering CRD types: %w", err)
	}

	for _, manifestPath := range openShiftCRDManifestPaths {
		file, err := os.Open(filepath.Join(repoDir, manifestPath))
		if err != nil {
			return fmt.Errorf("opening OpenShift manifest %s: %w", manifestPath, err)
		}
		objects, loadErr := kubernetes.LoadFromYAML(bufio.NewReader(file))
		closeErr := file.Close()
		if loadErr != nil {
			return fmt.Errorf("loading OpenShift manifest %s: %w", manifestPath, loadErr)
		}
		if closeErr != nil {
			return fmt.Errorf("closing OpenShift manifest %s: %w", manifestPath, closeErr)
		}
		for _, object := range objects {
			crd, ok := object.(*apiextensionsv1.CustomResourceDefinition)
			if !ok {
				return fmt.Errorf("OpenShift CRD manifest %s contains %T", manifestPath, object)
			}
			if err := r.Create(ctx, crd); err != nil {
				return fmt.Errorf("creating CustomResourceDefinition/%s: %w", crd.Name, err)
			}
			if err := wait.For(
				conditions.New(r).ResourceMatch(crd, func(object k8s.Object) bool {
					crd, ok := object.(*apiextensionsv1.CustomResourceDefinition)
					if !ok {
						return false
					}
					for _, condition := range crd.Status.Conditions {
						if condition.Type == apiextensionsv1.Established {
							return condition.Status == apiextensionsv1.ConditionTrue
						}
					}
					return false
				}),
				wait.WithContext(ctx),
				wait.WithTimeout(crdCreationTimeout),
			); err != nil {
				return fmt.Errorf("waiting for CustomResourceDefinition/%s: %w", crd.Name, err)
			}
		}
	}
	return nil
}

func (p *provisioner) createInfrastructureObject(ctx context.Context, client klient.Client, clusterName string) error {
	r := client.Resources()
	if err := configv1.Install(r.GetScheme()); err != nil {
		return fmt.Errorf("registering OpenShift config types: %w", err)
	}

	infrastructure := &configv1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.InfrastructureSpec{
			PlatformSpec: configv1.PlatformSpec{Type: configv1.NonePlatformType},
		},
	}
	if err := r.Create(ctx, infrastructure); err != nil {
		return fmt.Errorf("creating Infrastructure/cluster: %w", err)
	}

	infrastructure.Status = configv1.InfrastructureStatus{
		InfrastructureName: clusterName,
		Platform:           configv1.NonePlatformType,
		PlatformStatus:     &configv1.PlatformStatus{Type: configv1.NonePlatformType},
	}
	if err := r.UpdateStatus(ctx, infrastructure); err != nil {
		return fmt.Errorf("updating Infrastructure/cluster status: %w", err)
	}
	return nil
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

func (p *provisioner) writeKubeconfig(ctx context.Context, instanceName, containerName string, apiServerPort uint16) (string, error) {
	var kubeConfigErr error
	err := wait.For(
		func(ctx context.Context) (bool, error) {
			_, kubeConfigErr = p.containerExecOutput(ctx, containerName, nil, "/bin/test", "-f", kubeconfigPath)
			return kubeConfigErr == nil, nil
		},
		wait.WithContext(ctx),
		wait.WithTimeout(writeKubeconfigTimeout),
		wait.WithInterval(time.Second),
	)
	if err != nil {
		return "", errors.Join(fmt.Errorf("waiting for MicroShift kubeconfig: %w", err), kubeConfigErr)
	}

	contents, err := p.containerExecOutput(ctx, containerName, nil, "/bin/cat", kubeconfigPath)
	if err != nil {
		return "", fmt.Errorf("reading MicroShift kubeconfig: %w", err)
	}
	if !strings.Contains(contents, kubeconfigServer) {
		return "", fmt.Errorf("MicroShift kubeconfig does not contain expected server %q", kubeconfigServer)
	}
	contents = strings.Replace(
		contents,
		kubeconfigServer,
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

	bindings := result.Container.NetworkSettings.Ports[apiPort]
	if len(bindings) == 0 {
		return 0, false, fmt.Errorf("MicroShift container %s publishes no port for %s", containerName, apiPort)
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
		ExposedPorts: network.PortSet{apiPort: struct{}{}},
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
			apiPort: []network.PortBinding{{
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
		p.logger.Logf("microshift: container %s: %s", containerName, warning)
	}

	if _, err := p.client.ContainerStart(ctx, created.ID, dockerclient.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("starting MicroShift container %s: %w", containerName, err)
	}
	return nil
}

func (p *provisioner) stopContainer(ctx context.Context, containerName string) error {
	opts := dockerclient.ContainerStopOptions{
		Timeout: new(int(containerStopTimeout.Seconds())),
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

func microShiftImageForKubernetesVersion(kubernetesVersion, arch string) (string, error) {
	version, err := semver.NewVersion(kubernetesVersion)
	if err != nil {
		return "", fmt.Errorf("invalid Kubernetes version %q: %w", kubernetesVersion, err)
	}

	minor := fmt.Sprintf("%d.%d", version.Major(), version.Minor())
	image, found := imagesByKubernetesMinor[minor]
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
