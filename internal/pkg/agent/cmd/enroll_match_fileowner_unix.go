//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func getFileOwner(filePath string) (string, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to get file info: %w", err)
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("failed to get system specific file info: %w", err)
	}
	return strconv.FormatInt(int64(stat.Uid), 10), nil
}

func getCurrentUser() (string, error) {
	return strconv.Itoa(os.Geteuid()), nil
}

func isFileOwner(curUser string, fileOwner string) (bool, error) {
	return curUser == fileOwner, nil
}

func execWithFileOwnerFunc(fileOwner string, filePath string) (func() error, error) {
	u, err := user.LookupId(fileOwner)
	if err != nil {
		return nil, fmt.Errorf("error looking up user: %w", err)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("error converting gid to int: %w", err)
	}

	if err := unix.Setgid(gid); err != nil {
		return nil, fmt.Errorf("error setting gid: %w", err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("error converting uid to int: %w", err)
	}

	if err := unix.Setuid(uid); err != nil {
		return nil, fmt.Errorf("error setting uid: %w", err)
	}
	return func() error {
		return unix.Exec(filePath, os.Args, os.Environ())
	}, nil
}
