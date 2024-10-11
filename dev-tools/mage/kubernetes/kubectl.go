// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// KubectlApply applies the manifest file to the kubernetes cluster.
//
// KUBECONFIG must be in `env` to target a specific cluster.
func KubectlApply(env map[string]string, stdout, stderr io.Writer, filepath string) error {
	_, err := sh.Exec(
		env,
		stdout,
		stderr,
		"kubectl",
		"apply",
		"-f",
		filepath,
	)
	return err
}

// KubectlDelete deletes the resources from the manifest file from the kubernetes cluster.
//
// KUBECONFIG must be in `env` to target a specific cluster.
func KubectlDelete(env map[string]string, stdout, stderr io.Writer, filepath string) error {
	_, err := sh.Exec(
		env,
		stdout,
		stderr,
		"kubectl",
		"delete",
		"-f",
		filepath,
	)
	return err
}

// KubectlApplyInput applies the manifest string to the kubernetes cluster.
//
// KUBECONFIG must be in `env` to target a specific cluster.
func KubectlApplyInput(env map[string]string, stdout, stderr io.Writer, manifest string) error {
	return kubectlIn(env, stdout, stderr, manifest, "apply", "-f", "-")
}

// KubectlDeleteInput deletes the resources from the manifest string from the kubernetes cluster.
//
// KUBECONFIG must be in `env` to target a specific cluster.
func KubectlDeleteInput(env map[string]string, stdout, stderr io.Writer, manifest string) error {
	return kubectlIn(env, stdout, stderr, manifest, "delete", "-f", "-")
}

// KubectlWait waits for a condition to occur for a resource in the kubernetes cluster.
//
// KUBECONFIG must be in `env` to target a specific cluster.
func KubectlWait(env map[string]string, stdout, stderr io.Writer, waitFor, resource string, labels string) error {
	_, err := sh.Exec(
		env,
		stdout,
		stderr,
		"kubectl",
		"wait",
		"--timeout=300s",
		fmt.Sprintf("--for=%s", waitFor),
		resource,
		"-l",
		labels,
	)
	return err
}

func kubectlIn(env map[string]string, stdout, stderr io.Writer, input string, args ...string) error {
	c := exec.Command("kubectl", args...)
	c.Env = os.Environ()
	for k, v := range env {
		c.Env = append(c.Env, k+"="+v)
	}
	c.Stdout = stdout
	c.Stderr = stderr
	c.Stdin = strings.NewReader(input)

	if mg.Verbose() {
		fmt.Println("exec:", "kubectl", strings.Join(args, " "))
	}

	return c.Run()
}
