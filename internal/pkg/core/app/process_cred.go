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

// +build linux darwin

package app

import (
	"os"
	"os/user"
	"strconv"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/errors"
)

// UserGroup returns the uid and gid for the process specification.
func (spec ProcessSpec) UserGroup() (int, int, error) {
	if spec.User.Uid == "" && spec.Group.Gid == "" {
		// use own level
		return os.Geteuid(), os.Getegid(), nil
	}

	// check if user/group exists
	usedUID := spec.User.Uid
	userGID := ""
	if u, err := user.LookupId(spec.User.Uid); err != nil {
		u, err := user.Lookup(spec.User.Name)
		if err != nil {
			return 0, 0, err
		}
		usedUID = u.Uid
		userGID = u.Gid
	} else {
		userGID = u.Gid
	}

	usedGID := spec.Group.Gid
	if spec.Group.Gid != "" || spec.Group.Name != "" {
		if _, err := user.LookupGroupId(spec.Group.Gid); err != nil {
			g, err := user.LookupGroup(spec.Group.Name)
			if err != nil {
				return 0, 0, err
			}

			usedGID = g.Gid
		}
	} else {
		// if group is not specified and user is found, use users group
		usedGID = userGID
	}

	uid, err := strconv.Atoi(usedUID)
	if err != nil {
		return 0, 0, errors.New(err, "invalid user")
	}

	gid, _ := strconv.Atoi(usedGID)
	if err != nil {
		return 0, 0, errors.New(err, "invalid group")
	}

	return uid, gid, nil
}
