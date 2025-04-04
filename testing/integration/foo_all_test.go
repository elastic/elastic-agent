//go:build !windows

package integration

import (
	"os/exec"
	"syscall"
)

func stopCmd(cmd *exec.Cmd) error {
	return cmd.Process.Signal(syscall.SIGINT)
}

func getProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
