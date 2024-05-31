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
	"golang.org/x/crypto/ssh"
)

// Terraform globals
var terraformInstall *releases.ExactVersion
var terraform *tfexec.Terraform

func setup(ctx context.Context) (*ssh.Client, error) {
	// Setup terraform instances
	var err error
	terraform, err = prepareTerraform(ctx)
	if err != nil {
		return nil, fmt.Errorf("setup error: %w", err)
	}

	state, err := provision(ctx)

	if err != nil {
		return nil, fmt.Errorf("provisioning failed: %w", err)
	}

	// SSH into the machine to push local changes and other stuff
	privateKeyFile := state.Values.Outputs["private_key_file"].Value.(string)
	privateKeyFile = filepath.Join(testOpts.terraformWorkDir, privateKeyFile)
	pkBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("reading private key file %q: %w", privateKeyFile, err)
	}
	privateKey, err := ssh.ParsePrivateKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key from file %q: %w", privateKeyFile, err)
	}
	config := &ssh.ClientConfig{
		User: "buildkite-agent",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(privateKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	vmPublicAddress := state.Values.Outputs["vm_public_address"].Value.(string)
	// Add SSH port
	vmPublicAddress += ":22"
	client, err := ssh.Dial("tcp", vmPublicAddress, config)
	if err != nil {
		return nil, fmt.Errorf("connecting ssh %s@%s: %w", config.User, vmPublicAddress, err)
	}

	log.Printf("Connected via SSH to the machine as %s\n", client.User())

	//session, err := client.NewSession()
	//if err != nil {
	//	return nil, fmt.Errorf("initiating ssh session: %w", err)
	//}
	//defer session.Close()
	//
	//// PRE-COMMAND for setting up go and stuff
	////output, err := session.CombinedOutput("cd " + state.Values.Outputs["repo_dir"].Value.(string) + " && /opt/buildkite-agent/hooks/pre-command")
	//output, err := session.CombinedOutput(". $HOME/hooks/pre-command && asdf global golang 1.21.10")
	//log.Printf("pre-command hook output:\n%s\n", string(output))
	//if err != nil {
	//	return nil, fmt.Errorf("running pre-command hook: %w", err)
	//}
	return client, nil
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
