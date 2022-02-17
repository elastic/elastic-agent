// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// +build linux

package process

import (
	"context"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/elastic/elastic-agent/internal/pkg/core/logger"
)

func getCmd(ctx context.Context, logger *logger.Logger, path string, env []string, uid, gid int, arg ...string) *exec.Cmd {
	var cmd *exec.Cmd
	if ctx == nil {
		cmd = exec.Command(path, arg...)
	} else {
		cmd = exec.CommandContext(ctx, path, arg...)
	}
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, env...)
	cmd.Dir = filepath.Dir(path)
	if isInt32(uid) && isInt32(gid) {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			// on shutdown all sub-processes are sent SIGTERM, in the case that the Agent dies or is -9 killed
			// then also kill the children (only supported on linux)
			Pdeathsig: syscall.SIGKILL,
			Credential: &syscall.Credential{
				Uid:         uint32(uid),
				Gid:         uint32(gid),
				NoSetGroups: true,
			},
		}
	} else {
		logger.Errorf("provided uid or gid for %s is invalid. uid: '%d' gid: '%d'.", path, uid, gid)
	}

	return cmd
}

func isInt32(val int) bool {
	return val >= 0 && val <= math.MaxInt32
}

func terminateCmd(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}
