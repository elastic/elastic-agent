//go:build !windows

package upgrade

import "syscall"

var TestErrors = []error{
	syscall.ENOSPC,
	syscall.EDQUOT,
}
