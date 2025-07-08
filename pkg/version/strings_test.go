// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package version

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAgentVersionWithSnapshotFlag(t *testing.T) {
	type args struct {
		packageVersion string
		snapshotFlag   bool
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "simple major.minor.patch, no snapshot",
			args: args{
				packageVersion: "1.2.3",
				snapshotFlag:   false,
			},
			want:    "1.2.3",
			wantErr: assert.NoError,
		},
		{
			name: "simple major.minor.patch, snapshot",
			args: args{
				packageVersion: "1.2.3",
				snapshotFlag:   true,
			},
			want:    "1.2.3-SNAPSHOT",
			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch with prerelease, no snapshot",
			args: args{
				packageVersion: "1.2.3-prerelease",
				snapshotFlag:   false,
			},
			want:    "1.2.3-prerelease",
			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch with prerelease, snapshot",
			args: args{
				packageVersion: "1.2.3-prerelease",
				snapshotFlag:   true,
			},
			want:    "1.2.3-SNAPSHOT.prerelease",
			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch with build metadata, no snapshot",
			args: args{
				packageVersion: "1.2.3+build20240329125959",
				snapshotFlag:   false,
			},
			want:    "1.2.3+build20240329125959",
			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch with build metadata, snapshot",
			args: args{
				packageVersion: "1.2.3+build20240329125959",
				snapshotFlag:   true,
			},
			want:    "1.2.3-SNAPSHOT+build20240329125959",
			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch with prerelease and build metadata, no snapshot",
			args: args{
				packageVersion: "1.2.3-prerelease+build20240329125959",
				snapshotFlag:   false,
			},
			want:    "1.2.3-prerelease+build20240329125959",
			wantErr: assert.NoError,
		},
		{
			name: "major.minor.patch with with prerelease and build metadata, snapshot",
			args: args{
				packageVersion: "1.2.3-prerelease+build20240329125959",
				snapshotFlag:   true,
			},
			want:    "1.2.3-SNAPSHOT.prerelease+build20240329125959",
			wantErr: assert.NoError,
		},
		{
			name: "package version is not parseable, error happens only if snapshot flag is true",
			args: args{
				packageVersion: "aaa.bbb.ccc",
				snapshotFlag:   true,
			},
			want:    "",
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateAgentVersionWithSnapshotFlag(tt.args.packageVersion, tt.args.snapshotFlag)
			if !tt.wantErr(t, err, fmt.Sprintf("GenerateAgentVersionWithSnapshotFlag(%v, %v)", tt.args.packageVersion, tt.args.snapshotFlag)) {
				return
			}
			assert.Equalf(t, tt.want, got, "GenerateAgentVersionWithSnapshotFlag(%v, %v)", tt.args.packageVersion, tt.args.snapshotFlag)
		})
	}
}
