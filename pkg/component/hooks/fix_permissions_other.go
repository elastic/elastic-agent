// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package hooks

import (
	"fmt"
	"math"
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/install/usermgmt"
	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func FixPermissions(path string, _ bool, username string, groupname string, failOnNotExist bool, mask int) error {
	// only valid config is
	var uid, gid = -1, -1
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

	var opts []perms.OptFunc
	if uid != -1 || gid != -1 {
		ownership := utils.FileOwner{}
		ownership.GID = gid
		ownership.UID = uid
		opts = append(opts, perms.WithOwnership(ownership))
	}

	if mask > math.MaxInt32 {
		return fmt.Errorf("mask %d nout of range expected 0-%d", mask, math.MaxInt32)
	}

	if mask > 0 {
		opts = append(opts, perms.WithMask(os.FileMode(mask))) //nolint:gosec // G115 Conversion from int to uint32 is safe here.
	}

	err = perms.FixPermissions(path, opts...)
	if os.IsNotExist(err) && !failOnNotExist {
		return nil
	}

	return err
}
