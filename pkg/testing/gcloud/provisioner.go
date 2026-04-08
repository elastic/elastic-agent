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

	// Build labels string
	var labelParts []string
	for k, v := range instanceLabels {
		labelParts = append(labelParts, fmt.Sprintf("%s=%s", k, v))
	}

	p.logger.Logf("Creating instance %s (machine=%s, image=%s/%s, zone=%s)",
		instanceName, layout.InstanceSize, layout.ImageProject, layout.ImageFamily, p.cfg.Datacenter)

	createCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	args := []string{
		"compute", "instances", "create", instanceName,
		"--zone", p.cfg.Datacenter,
		"--machine-type", layout.InstanceSize,
		"--image-family", layout.ImageFamily,
		"--image-project", layout.ImageProject,
		"--boot-disk-size", "50GB",
		"--labels", strings.Join(labelParts, ","),
		"--format", "json",
		"--quiet",
	}

	if batch.OS.Type == define.Windows {
		// Windows needs a startup script to install OpenSSH and configure the public key.
		// The enable-windows-ssh metadata alone is not sufficient for key-based auth.
		startupScript := windowsStartupScript(layout.Username, strings.TrimSpace(publicKey))
		scriptFile, err := os.CreateTemp("", "gcloud-windows-startup-*.ps1")
		if err != nil {
			return common.Instance{}, fmt.Errorf("failed to create startup script: %w", err)
		}
		defer os.Remove(scriptFile.Name())
		if _, err := scriptFile.WriteString(startupScript); err != nil {
			scriptFile.Close()
			return common.Instance{}, fmt.Errorf("failed to write startup script: %w", err)
		}
		scriptFile.Close()

		args = append(args,
			"--metadata-from-file", fmt.Sprintf("windows-startup-script-ps1=%s", scriptFile.Name()),
			"--metadata", fmt.Sprintf("ssh-keys=%s,enable-windows-ssh=TRUE", sshMeta),
		)
	} else {
		args = append(args, "--metadata", fmt.Sprintf("ssh-keys=%s", sshMeta))
	}

	output, err := p.run(createCtx, args...)
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

// windowsStartupScript returns a PowerShell script that installs and configures
// OpenSSH server on a Windows GCE instance, including adding the provided SSH
// public key for the given user and setting the default shell to PowerShell.
func windowsStartupScript(username, publicKey string) string {
	return fmt.Sprintf(`
# Install Chocolatey
[System.Net.ServicePointManager]::SecurityProtocol = 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start and enable the SSH service
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# Configure firewall rule for SSH
New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (sshd)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue

# Set cmd.exe as default shell (the test runner expects cmd, not PowerShell)
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\cmd.exe" -PropertyType String -Force

# Create user profile directory if needed
$profilePath = "C:\Users\%s"
if (-not (Test-Path $profilePath)) {
    New-Item -ItemType Directory -Path $profilePath -Force
}

# Set up authorized_keys for administrators group
$sshDir = "C:\ProgramData\ssh"
if (-not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir -Force
}
$authorizedKeysFile = Join-Path $sshDir "administrators_authorized_keys"
Set-Content -Path $authorizedKeysFile -Value "%s"

# Fix permissions on authorized_keys file
icacls $authorizedKeysFile /inheritance:r /grant "SYSTEM:(F)" /grant "BUILTIN\Administrators:(F)"

# Also set up user-level authorized_keys
$userSshDir = Join-Path $profilePath ".ssh"
if (-not (Test-Path $userSshDir)) {
    New-Item -ItemType Directory -Path $userSshDir -Force
}
$userAuthorizedKeys = Join-Path $userSshDir "authorized_keys"
Set-Content -Path $userAuthorizedKeys -Value "%s"

# Restart sshd to pick up configuration changes
Restart-Service sshd
`, username, publicKey, publicKey)
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
