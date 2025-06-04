package filelock

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/stretchr/testify/assert"
)

func TestFileLocker_Lock(t *testing.T) {
	type fields struct {
		fileLock             *flock.Flock
		blocking             bool
		timeout              time.Duration
		customNotLockedError error
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr assert.ErrorAssertionFunc
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl := &FileLocker{
				fileLock:             tt.fields.fileLock,
				blocking:             tt.fields.blocking,
				timeout:              tt.fields.timeout,
				customNotLockedError: tt.fields.customNotLockedError,
			}
			tt.wantErr(t, fl.Lock(), fmt.Sprintf("Lock()"))
		})
	}
}

func TestFileLocker_LockContext(t *testing.T) {
	type fields struct {
		fileLock             *flock.Flock
		blocking             bool
		timeout              time.Duration
		customNotLockedError error
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl := &FileLocker{
				fileLock:             tt.fields.fileLock,
				blocking:             tt.fields.blocking,
				timeout:              tt.fields.timeout,
				customNotLockedError: tt.fields.customNotLockedError,
			}
			tt.wantErr(t, fl.LockContext(tt.args.ctx), fmt.Sprintf("LockContext(%v)", tt.args.ctx))
		})
	}
}

func TestFileLocker_Unlock(t *testing.T) {
	type fields struct {
		fileLock             *flock.Flock
		blocking             bool
		timeout              time.Duration
		customNotLockedError error
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr assert.ErrorAssertionFunc
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl := &FileLocker{
				fileLock:             tt.fields.fileLock,
				blocking:             tt.fields.blocking,
				timeout:              tt.fields.timeout,
				customNotLockedError: tt.fields.customNotLockedError,
			}
			tt.wantErr(t, fl.Unlock(), fmt.Sprintf("Unlock()"))
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
			want:    nil,
			wantErr: assert.Error,
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
