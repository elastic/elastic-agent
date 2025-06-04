// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package filelock

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileLocker_Lock(t *testing.T) {

	type testHook func(t *testing.T, workDir string, fl *FileLocker)

	type args struct {
		lockFilePath string
		opts         []FileLockerOption
	}

	tests := []struct {
		name             string
		args             args
		beforeLocking    testHook
		afterLocking     testHook
		afterUnlocking   testHook
		wantLockingErr   assert.ErrorAssertionFunc
		wantUnlockingErr assert.ErrorAssertionFunc
	}{
		{
			name: "Non-blocking, verify that it's re-lockable",
			args: args{
				lockFilePath: "nb-relock.lock",
				opts:         nil,
			},
			beforeLocking: nil,
			afterLocking:  nil,
			afterUnlocking: func(t *testing.T, workDir string, fl *FileLocker) {
				// recreate a lock with the same path and verify that it succeeds
				newFl, err := NewFileLocker(fl.fileLock.String())
				require.NoErrorf(t, err, "there should be no error creating another locker on file %q", fl.fileLock.String())
				err = newFl.Lock()
				require.NoErrorf(t, err, "there should be no error re-locking file %q", newFl.fileLock.String())
				err = newFl.Unlock()
				require.NoErrorf(t, err, "there should be no error re-unlocking file %q", newFl.fileLock.String())
			},
			wantLockingErr:   assert.NoError,
			wantUnlockingErr: assert.NoError,
		},
		{
			name: "blocking, verify that it's re-lockable",
			args: args{
				lockFilePath: "b-relock.lock",
				opts:         []FileLockerOption{WithTimeout(1 * time.Second)},
			},
			beforeLocking: nil,
			afterLocking:  nil,
			afterUnlocking: func(t *testing.T, workDir string, fl *FileLocker) {
				// recreate a lock with the same path and verify that it succeeds
				newFl, err := NewFileLocker(fl.fileLock.String(), WithTimeout(1*time.Second))
				require.NoErrorf(t, err, "there should be no error creating another locker on file %q", fl.fileLock.String())
				err = newFl.Lock()
				require.NoErrorf(t, err, "there should be no error re-locking file %q", newFl.fileLock.String())
				err = newFl.Unlock()
				require.NoErrorf(t, err, "there should be no error re-unlocking file %q", newFl.fileLock.String())
			},
			wantLockingErr:   assert.NoError,
			wantUnlockingErr: assert.NoError,
		},
		{
			name: "Non-blocking, default error when file is already locked from the same process",
			args: args{
				lockFilePath: "nb-failock.lock",
				opts:         nil,
			},
			beforeLocking: func(t *testing.T, workDir string, fl *FileLocker) {
				// create a lock with the same path and verify that the first locker returns an error
				newFl, err := NewFileLocker(fl.fileLock.String())
				require.NoErrorf(t, err, "there should be no error creating another locker on file %q", fl.fileLock.String())
				err = newFl.Lock()
				require.NoErrorf(t, err, "there should be no error first locking file %q", newFl.fileLock.String())

				t.Cleanup(func() {
					errUnlock := newFl.Unlock()
					assert.NoError(t, errUnlock)
				})
			},
			afterLocking:     nil,
			afterUnlocking:   nil,
			wantLockingErr:   assert.Error,
			wantUnlockingErr: assert.NoError,
		},
		{
			name: "blocking, keeps trying when file is initially already locked from the same process",
			args: args{
				lockFilePath: "b-failock.lock",
				opts:         []FileLockerOption{WithTimeout(30 * time.Second)},
			},
			beforeLocking: func(t *testing.T, workDir string, fl *FileLocker) {
				// create a lock with the same path and verify that the first locker does not return an error
				newFl, err := NewFileLocker(fl.fileLock.String())
				require.NoErrorf(t, err, "there should be no error creating another locker on file %q", fl.fileLock.String())

				err = newFl.Lock()
				require.NoErrorf(t, err, "there should be no error first locking file %q", newFl.fileLock.String())

				// start a goroutine that will unlock after a few seconds
				go func() {
					select {
					case <-t.Context().Done():
						assert.Fail(t, "Test context expired prematurely")

					case <-time.After(5 * time.Second):
						errUnlock := newFl.Unlock()
						assert.NoError(t, errUnlock)
					}
				}()
			},
			afterLocking:     nil,
			afterUnlocking:   nil,
			wantLockingErr:   assert.NoError,
			wantUnlockingErr: assert.NoError,
		},
		{
			name: "blocking, fails when file is already locked by another process",
			args: args{
				lockFilePath: "b-failockext.lock",
				opts:         []FileLockerOption{WithTimeout(30 * time.Second)},
			},
			beforeLocking: func(t *testing.T, workDir string, fl *FileLocker) {
				//  launch a process that will lock with the same path
				lockerCmdCancel, lockerCmd := createFileLockerCmd(t, fl.fileLock.String())

				fileLockerStdErr, err := lockerCmd.StderrPipe()
				require.NoError(t, err, "Error getting stderr pipe from filelocker")

				fileLockedCh := make(chan struct{})

				// consume stderr to check for locking
				go func() {
					scanner := bufio.NewScanner(fileLockerStdErr)
					for scanner.Scan() {
						line := scanner.Text()
						if strings.Contains(line, "Acquired lock on file") {
							fileLockedCh <- struct{}{}
						}
					}
				}()

				err = lockerCmd.Start()
				require.NoError(t, err, "running filelocker should not fail")

				t.Cleanup(func() {
					lockerCmdCancel()
					_ = lockerCmd.Wait()
				})

				// wait until the external process acquires the lock
				<-fileLockedCh
			},
			afterLocking:     nil,
			afterUnlocking:   nil,
			wantLockingErr:   assert.Error,
			wantUnlockingErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tmpDir := t.TempDir()

			fl, err := NewFileLocker(filepath.Join(tmpDir, tt.args.lockFilePath), tt.args.opts...)
			require.NoError(t, err, "error instantiating file locker")

			if tt.beforeLocking != nil {
				tt.beforeLocking(t, tmpDir, fl)
			}

			tt.wantLockingErr(t, fl.Lock(), fmt.Sprintf("Lock()"))
			if tt.afterLocking != nil {
				tt.afterLocking(t, tmpDir, fl)
			}

			tt.wantUnlockingErr(t, fl.Unlock(), fmt.Sprintf("Unlock()"))
			if tt.afterUnlocking != nil {
				tt.afterUnlocking(t, tmpDir, fl)
			}
		})
	}
}

func TestNewFileLocker(t *testing.T) {
	type args struct {
		lockFilePath string
		opts         []FileLockerOption
	}
	tests := []struct {
		name    string
		args    args
		want    *FileLocker
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "Default FileLocker should be non-blocking",
			args: args{
				lockFilePath: "somefile.lock",
				opts:         nil,
			},
			want: &FileLocker{
				fileLock:             flock.New(filepath.Join("somefile.lock")),
				blocking:             false,
				timeout:              0,
				customNotLockedError: nil,
			},
			wantErr: assert.NoError,
		},
		{
			name: "WithTimeout creates a blocking FileLocker",
			args: args{
				lockFilePath: "somefile.lock",
				opts:         []FileLockerOption{WithTimeout(10 * time.Second)},
			},
			want: &FileLocker{
				fileLock:             flock.New(filepath.Join("somefile.lock")),
				blocking:             true,
				timeout:              10 * time.Second,
				customNotLockedError: nil,
			},
			wantErr: assert.NoError,
		},
		{
			name: "Zero Timeout for a blocking FileLocker errors out",
			args: args{
				lockFilePath: "somefile.lock",
				opts:         []FileLockerOption{WithTimeout(0)},
			},
			want:    nil,
			wantErr: assert.Error,
		},
		{
			name: "It's possible to specify a custom NotLocked Error",
			args: args{
				lockFilePath: "somefile.lock",
				opts:         []FileLockerOption{WithCustomNotLockedError(errors.New("some custom error"))},
			},
			want: &FileLocker{
				fileLock:             flock.New(filepath.Join("somefile.lock")),
				blocking:             false,
				timeout:              0,
				customNotLockedError: errors.New("some custom error"),
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFileLocker(tt.args.lockFilePath, tt.args.opts...)
			if !tt.wantErr(t, err, fmt.Sprintf("NewFileLocker(%v, %v)", tt.args.lockFilePath, tt.args.opts)) {
				return
			}
			assert.Equalf(t, tt.want, got, "NewFileLocker(%v, %v)", tt.args.lockFilePath, tt.args.opts)
		})
	}
}

func createFileLockerCmd(t *testing.T, lockFilePath string) (context.CancelFunc, *exec.Cmd) {
	executableName := "testlocker"
	if runtime.GOOS == "windows" {
		executableName += ".exe"
	}
	filelockerExecutablePath := filepath.Join("testlocker", executableName)
	require.FileExistsf(
		t,
		filelockerExecutablePath,
		"testlocker executable %s should exist. Please ensure that mage build:testbinaries has been executed.",
		filelockerExecutablePath,
	)

	cmdCtx, cmdCancel := context.WithCancel(t.Context())
	lockFileCmd := exec.CommandContext(cmdCtx, filelockerExecutablePath, "-lockfile", lockFilePath)
	return cmdCancel, lockFileCmd
}
