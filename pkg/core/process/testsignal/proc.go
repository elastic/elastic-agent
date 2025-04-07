//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

func stopCmd(cmd *exec.Cmd) error {
	return cmd.Process.Signal(syscall.SIGINT)
}

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
