// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package gcloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/elastic/elastic-agent/pkg/core/process"
	"github.com/elastic/elastic-agent/pkg/testing/common"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/runner"
)

const (
	Name = "gcloud"
)

// instanceLabels are applied to all created GCE instances.
var instanceLabels = map[string]string{
	"division": "engineering",
	"org":      "obs",
	"team":     "elastic-agent-control-plane",
	"project":  "elastic-agent",
}

type provisioner struct {
	logger common.Logger
	cfg    Config
}

// NewProvisioner creates the gcloud provisioner.
func NewProvisioner(cfg Config) (common.InstanceProvisioner, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	return &provisioner{cfg: cfg}, nil
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

// Supported returns true when the provisioner supports the given OS.
func (p *provisioner) Supported(os define.OS) bool {
	_, ok := findOSLayout(os)
	return ok
}

// Provision creates GCE instances for the given batches.
func (p *provisioner) Provision(ctx context.Context, cfg common.Config, batches []common.OSBatch) ([]common.Instance, error) {
	err := p.activateServiceAccount(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to activate service account: %w", err)
	}

	publicKeyPath := filepath.Join(cfg.StateDir, "id_rsa.pub")
	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH public key at %s: %w", publicKeyPath, err)
	}

	g, gCtx := errgroup.WithContext(ctx)
	instances := make([]common.Instance, len(batches))
	for i, batch := range batches {
		g.Go(func() error {
			inst, err := p.createInstance(gCtx, batch, string(publicKey))
			if err != nil {
				return fmt.Errorf("failed to create instance for batch %s: %w", batch.ID, err)
			}
			instances[i] = inst
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		// best-effort cleanup of any instances that were created
		p.cleanupInstances(ctx, instances)
		return nil, err
	}
	return instances, nil
}

// Clean deletes all provisioned instances.
func (p *provisioner) Clean(ctx context.Context, _ common.Config, instances []common.Instance) error {
	p.cleanupInstances(ctx, instances)
	return nil
}

func (p *provisioner) cleanupInstances(ctx context.Context, instances []common.Instance) {
	g, gCtx := errgroup.WithContext(ctx)
	for _, inst := range instances {
		if inst.Name == "" {
			continue
		}
		g.Go(func() error {
			deleteCtx, cancel := context.WithTimeout(gCtx, 5*time.Minute)
			defer cancel()
			err := p.deleteInstance(deleteCtx, inst.Name)
			if err != nil {
				p.logger.Logf("Failed to delete instance %s: %s", inst.Name, err)
			}
			return nil // don't stop other deletions
		})
	}
	_ = g.Wait()
}

func (p *provisioner) activateServiceAccount(ctx context.Context) error {
	p.logger.Logf("Activating GCP service account")
	projectID, err := p.cfg.ProjectID()
	if err != nil {
		return err
	}
	_, err = p.run(ctx, "auth", "activate-service-account",
		"--key-file", p.cfg.ServiceTokenPath,
		"--project", projectID,
	)
	return err
}

func (p *provisioner) createInstance(ctx context.Context, batch common.OSBatch, publicKey string) (common.Instance, error) {
	layout, ok := findOSLayout(batch.OS.OS)
	if !ok {
		return common.Instance{}, fmt.Errorf("unsupported OS: %s/%s", batch.OS.Type, batch.OS.Arch)
	}

	instanceName := sanitizeInstanceName(batch.ID)
	sshMeta := fmt.Sprintf("%s:%s", layout.Username, strings.TrimSpace(publicKey))

	// Build metadata string
	metadata := fmt.Sprintf("ssh-keys=%s", sshMeta)
	if batch.OS.Type == define.Windows {
		metadata += ",enable-windows-ssh=TRUE"
	}

	// Build labels string
	var labelParts []string
	for k, v := range instanceLabels {
		labelParts = append(labelParts, fmt.Sprintf("%s=%s", k, v))
	}

	p.logger.Logf("Creating instance %s (machine=%s, image=%s/%s, zone=%s)",
		instanceName, layout.InstanceSize, layout.ImageProject, layout.ImageFamily, p.cfg.Datacenter)

	createCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	output, err := p.run(createCtx, "compute", "instances", "create", instanceName,
		"--zone", p.cfg.Datacenter,
		"--machine-type", layout.InstanceSize,
		"--image-family", layout.ImageFamily,
		"--image-project", layout.ImageProject,
		"--boot-disk-size", "50GB",
		"--metadata", metadata,
		"--labels", strings.Join(labelParts, ","),
		"--format", "json",
		"--quiet",
	)
	if err != nil {
		return common.Instance{}, fmt.Errorf("gcloud compute instances create failed: %w", err)
	}

	// Parse the JSON output to get the external IP
	var created []gceInstance
	if err := json.Unmarshal(output, &created); err != nil {
		return common.Instance{}, fmt.Errorf("failed to parse gcloud create output: %w", err)
	}
	if len(created) == 0 {
		return common.Instance{}, fmt.Errorf("gcloud create returned no instances")
	}

	ip := created[0].externalIP()
	if ip == "" {
		return common.Instance{}, fmt.Errorf("instance %s has no external IP", instanceName)
	}

	p.logger.Logf("Instance %s created at %s", instanceName, ip)

	return common.Instance{
		ID:          batch.ID,
		Provisioner: Name,
		Name:        instanceName,
		IP:          ip,
		Username:    layout.Username,
		RemotePath:  layout.RemotePath,
		Internal: map[string]interface{}{
			"zone": p.cfg.Datacenter,
		},
	}, nil
}

func (p *provisioner) deleteInstance(ctx context.Context, name string) error {
	p.logger.Logf("Deleting instance %s", name)
	_, err := p.run(ctx, "compute", "instances", "delete", name,
		"--zone", p.cfg.Datacenter,
		"--quiet",
	)
	return err
}

// run executes a gcloud command and returns its stdout.
func (p *provisioner) run(ctx context.Context, args ...string) ([]byte, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	proc, err := process.Start("gcloud",
		process.WithContext(ctx),
		process.WithArgs(args),
		process.WithCmdOptions(runner.AttachOut(&stdout), runner.AttachErr(&stderr)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start gcloud %s: %w", args[0], err)
	}
	ps := <-proc.Wait()
	if ps.ExitCode() != 0 {
		return nil, fmt.Errorf("gcloud %s exited with code %d: %s", strings.Join(args, " "), ps.ExitCode(), stderr.String())
	}
	return stdout.Bytes(), nil
}

// gceInstance represents the JSON output from gcloud compute instances create/describe.
type gceInstance struct {
	Name              string             `json:"name"`
	Status            string             `json:"status"`
	NetworkInterfaces []networkInterface `json:"networkInterfaces"`
}

type networkInterface struct {
	AccessConfigs []accessConfig `json:"accessConfigs"`
}

type accessConfig struct {
	NatIP string `json:"natIP"`
}

func (i gceInstance) externalIP() string {
	for _, ni := range i.NetworkInterfaces {
		for _, ac := range ni.AccessConfigs {
			if ac.NatIP != "" {
				return ac.NatIP
			}
		}
	}
	return ""
}

// sanitizeInstanceName converts a batch ID into a valid GCE instance name.
// GCE names must be lowercase, start with a letter, contain only letters/numbers/hyphens, max 63 chars.
var invalidGCEChars = regexp.MustCompile(`[^a-z0-9-]`)

func sanitizeInstanceName(batchID string) string {
	name := strings.ToLower(batchID)
	name = invalidGCEChars.ReplaceAllString(name, "-")
	// ensure starts with a letter
	if len(name) > 0 && (name[0] < 'a' || name[0] > 'z') {
		name = "vm-" + name
	}
	// truncate to 63 chars
	if len(name) > 63 {
		name = name[:63]
	}
	// remove trailing hyphens
	name = strings.TrimRight(name, "-")
	return name
}
