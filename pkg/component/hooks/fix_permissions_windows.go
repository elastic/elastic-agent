// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package hooks

import (
	"fmt"
	"math"
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/install/usermgmt"
	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func FixPermissions(path string, inheritPermissions bool, username string, groupname string, failOnNotExist bool, mask int) error {
	//         - hook_type: "apply-permissions"
	//           args:
	//             path: "/opt/elastic/metricbeat" // relative paths will be prefixed with components path
	//			   target_os: [windows]
	//             user: root
	//             group: root
	//             fail_on_path_not_exist: false
	//             mask: 0770 # default 0770 if not specified
	//             # windows specific
	//             inherit_permissions: false

	// only valid config is
	var uid, gid string
	var err error
	if len(username) > 0 {
		uid, err = usermgmt.FindUID(username)
		if err != nil {
			return err
		}
	}

	// group is also provided
	if len(groupname) > 0 {
		gid, err = usermgmt.FindGID(groupname)
		if err != nil {
			return err
		}
	}

	if mask > math.MaxInt32 {
		return fmt.Errorf("mask %d nout of range expected 0-%d", mask, math.MaxInt32)
	}

	var opts []perms.OptFunc
	if len(uid) != 0 || len(gid) != 0 {
		ownership := utils.FileOwner{}
		ownership.GID = gid
		ownership.UID = uid
		opts = append(opts, perms.WithOwnership(ownership))
	}

	opts = append(opts, perms.WithInherit(inheritPermissions))

	if mask > 0 {
		opts = append(opts, perms.WithMask(os.FileMode(mask)))
	}

	err = perms.FixPermissions(path, opts...)
	if os.IsNotExist(err) && !failOnNotExist {
		return nil
	}

	return err
}
