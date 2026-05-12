// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"fmt"
	"os/user"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install/componentvalidation"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/utils"
)

type reexecCoordinator interface {
	ReExec(callback reexec.ShutdownCallbackFn, argOverrides ...string)
}

type PrivilegeLevelChange struct {
	log   *logger.Logger
	coord reexecCoordinator
	ch    chan coordinator.ConfigChange
}

func NewPrivilegeLevelChange(
	log *logger.Logger,
	coord reexecCoordinator,
	ch chan coordinator.ConfigChange,
) *PrivilegeLevelChange {
	return &PrivilegeLevelChange{
		log:   log,
		coord: coord,
		ch:    ch,
	}
}

// Handle handles PRIVILEGE_LEVEL_CHANGE action.
func (h *PrivilegeLevelChange) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	return h.handle(ctx, a, acker)
}

func (h *PrivilegeLevelChange) handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) (rerr error) {
	action, ok := a.(*fleetapi.ActionPrivilegeLevelChange)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionPrivilegeLevelChange and received %T", a)
	}

	defer func() {
		if rerr != nil {
			h.ackFailure(ctx, rerr, action, acker)
		}
	}()

	isRoot, err := utils.HasRoot()
	if err != nil {
		return fmt.Errorf("failed to determine root/Administrator: %w", err)
	}

	return h.handleChange(ctx, a, acker, action, isRoot)
}

func (h *PrivilegeLevelChange) handleChange(ctx context.Context, a fleetapi.Action, acker acker.Acker, action *fleetapi.ActionPrivilegeLevelChange, isRoot bool) (rerr error) {
	if !action.Data.Unprivileged {
		// only unprivileged supported at this point
		return fmt.Errorf("unsupported action, ActionPrivilegeLevelChange supports only downgrading permissions")
	}

	var username, groupname, password string
	if action.Data.UserInfo != nil {
		username = action.Data.UserInfo.Username
		groupname = action.Data.UserInfo.Groupname
		password = action.Data.UserInfo.Password
	}
	username, password = install.UnprivilegedUser(username, password)
	groupname = install.UnprivilegedGroup(groupname)

	ackCommitFn := func() {
		if err := acker.Ack(ctx, a); err != nil {
			h.log.Errorw("failed to ACK an action",
				"error.message", err,
				"action", a)
		}
		if err := acker.Commit(ctx); err != nil {
			h.log.Errorw("failed to commit ACK of an action",
				"error.message", err,
				"action", a)
		}
	}

	if !isRoot {
		// check if we're already running as the desired user
		gid, err := install.FindGID(groupname)
		if err != nil {
			return fmt.Errorf("failed to find GID for group %s: %w", groupname, err)
		}
		uid, err := install.FindUID(username)
		if err != nil {
			return fmt.Errorf("failed to find UID for user %s: %w", username, err)
		}

		currentUser, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to get current user: %w", err)
		}

		if targetingSameUser(currentUser.Uid, currentUser.Gid, fmt.Sprint(uid), fmt.Sprint(gid)) {
			// already running as desired user, do not fail the action
			// some form of deduplication
			h.log.Infof("already running as user %s and group %s, no changes required", username, groupname)
			// ack action so it's not hanging
			ackCommitFn()
			return nil
		}

		return fmt.Errorf("can change privilege level only when running as root/Administrator")
	}

	// ensure no component issues
	err := componentvalidation.EnsureNoServiceComponentIssues()
	if err != nil {
		h.log.Debugf("handlerPrivilegeLevelChange: found issues with components: %v", err)
		return err
	}

	// apply empty config to stop processing
	stopComponents(ctx, h.ch, a, acker, nil)

	// fix permissions
	topPath := paths.Top()
	_, err = install.SwitchServiceUser(topPath, &debugDescriber{h.log}, username, groupname, password)
	if err != nil {
		// error already adds context
		return err
	}

	// ack
	ackCommitFn()

	// check everything is properly set up
	userName, groupName, err := install.GetDesiredUser()
	if err != nil {
		return fmt.Errorf("failed to determine target user: %w", err)
	}

	if userName != "" || groupName != "" {
		_, err = install.EnsureUserAndGroup(userName, groupName, &debugDescriber{h.log}, true)
		if err != nil {
			return fmt.Errorf("failed to setup user: %w", err)
		}
	}

	// restart
	h.coord.ReExec(nil)
	return nil
}

func targetingSameUser(currentUID, currentGID, targetUID, targetGID string) bool {
	return currentGID == targetGID && currentUID == targetUID
}

func (h *PrivilegeLevelChange) ackFailure(ctx context.Context, err error, action *fleetapi.ActionPrivilegeLevelChange, acker acker.Acker) {
	action.Err = err

	if err := acker.Ack(ctx, action); err != nil {
		h.log.Errorw("failed to ack privilege level change action",
			"error.message", err,
			"action", action)
	}

	if err := acker.Commit(ctx); err != nil {
		h.log.Errorw("failed to commit privilege level change action",
			"error.message", err,
			"action", action)
	}
}

type debugDescriber struct {
	l *logger.Logger
}

func (d *debugDescriber) Describe(a string) {
	d.l.Debug(a)
}
