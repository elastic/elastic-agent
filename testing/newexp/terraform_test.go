//go:build integration

package newexp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/terraform-exec/tfexec"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/crypto/ssh"
)

type RemoteMachine struct {
	Name                string `mapstructure:"name,omitempty"`
	Platform            string `mapstructure:"platform,omitempty"`
	PublicIP            string `mapstructure:"public_ip,omitempty"`
	SSHUser             string `mapstructure:"ssh_user,omitempty"`
	SSHKey              string `mapstructure:"ssh_key,omitempty"`
	RepositoryDirectory string `mapstructure:"repo_dir,omitempty"`
}

type ESSDeployment struct {
	Name              string `mapstructure:"name"`
	Version           string `mapstructure:"version"`
	Region            string `mapstructure:"region"`
	ESUser            string `mapstructure:"es_user"`
	ESPassword        string `mapstructure:"es_password"`
	ElasticsearchHost string `mapstructure:"es_host"`
	KibanaHost        string `mapstructure:"kibana_host"`
}

// Terraform globals
var terraformInstall *releases.ExactVersion
var terraform *tfexec.Terraform

func setup(ctx context.Context) (*ssh.Client, *RemoteMachine, *ESSDeployment, error) {
	// Setup terraform instances
	var err error
	terraform, err = prepareTerraform(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup error: %w", err)
	}

	state, err := provision(ctx)

	if err != nil {
		return nil, nil, nil, fmt.Errorf("provisioning failed: %w", err)
	}

	// get the VM details
	testMachine := new(RemoteMachine)
	err = mapstructure.Decode(state.Values.Outputs["test_machine"].Value, testMachine)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding terraform test_machine output: %w", err)
	}

	// get the ESS deployment details
	essDeployment := new(ESSDeployment)
	err = mapstructure.Decode(state.Values.Outputs["ess-deployment"].Value, essDeployment)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding terraform ess-deployment output: %w", err)
	}

	// SSH into the machine to push local changes and other stuff
	testMachine.SSHKey = filepath.Join(testOpts.terraformWorkDir, testMachine.SSHKey)
	pkBytes, err := os.ReadFile(testMachine.SSHKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading private key file %q: %w", testMachine.SSHKey, err)
	}
	privateKey, err := ssh.ParsePrivateKey(pkBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing private key from file %q: %w", testMachine.SSHKey, err)
	}
	config := &ssh.ClientConfig{
		User: testMachine.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(privateKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	// Add SSH port
	vmPublicAddress := testMachine.PublicIP + ":22"
	client, err := ssh.Dial("tcp", vmPublicAddress, config)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connecting ssh %s@%s: %w", config.User, vmPublicAddress, err)
	}

	log.Printf("Connected via SSH to the machine as %s\n", client.User())

	return client, testMachine, essDeployment, nil
}

func provision(ctx context.Context) (*tfjson.State, error) {
	err := terraform.Init(ctx, tfexec.Upgrade(true))
	if err != nil {
		return nil, fmt.Errorf("error running Init: %w", err)
	}

	planFilePath := filepath.Join(testOpts.terraformWorkDir, "main.tfplan")
	tfvarsFilePath := filepath.Join(testOpts.terraformWorkDir, "main.tfvars")
	changesRequired, err := terraform.Plan(ctx, tfexec.VarFile(tfvarsFilePath), tfexec.Out(planFilePath))
	if err != nil {
		return nil, fmt.Errorf("error running Plan: %w", err)
	}

	if !changesRequired {
		// there are no changes required
		return terraform.Show(ctx)
	}

	err = terraform.Apply(ctx, tfexec.DirOrPlan(planFilePath))
	if err != nil {
		return nil, fmt.Errorf("error running Apply: %w", err)
	}

	// FIXME the command below shows sensitive output id stdout is set
	terraform.SetStdout(nil)
	state, err := terraform.Show(ctx)
	terraform.SetStdout(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("error running Show: %w", err)
	}

	return state, nil
}

func tearDown(ctx context.Context) error {
	if testOpts.skipDestroy {
		return nil
	}

	if terraform == nil {
		// terraform does not seem to be installed properly
		return fmt.Errorf("terraform does not seem to install correctly")
	}

	teardownError := terraform.Destroy(ctx, tfexec.VarFile(filepath.Join(testOpts.terraformWorkDir, "main.tfvars")))
	return errors.Join(teardownError, terraformInstall.Remove(ctx))
}

func prepareTerraform(ctx context.Context) (*tfexec.Terraform, error) {
	installer := &releases.ExactVersion{
		Product: product.Terraform,
		Version: version.Must(version.NewVersion("1.8.4")),
	}
	execPath, err := installer.Install(ctx)
	if err != nil {
		return nil, fmt.Errorf("error installing Terraform: %w", err)
	}
	terraformInstall = installer

	log.Printf("Installed terraform, exec path: %s\n", execPath)

	log.Printf("working dir: %s\n", testOpts.terraformWorkDir)

	tf, err := tfexec.NewTerraform(testOpts.terraformWorkDir, execPath)
	tf.SetLogger(log.Default())
	tf.SetStdout(os.Stderr)
	if err != nil {
		log.Fatalf("error running NewTerraform: %s", err)
	}

	return tf, nil
}
