// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	"github.com/elastic/elastic-agent/internal/pkg/agent/install/componentvalidation"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker"
	"github.com/elastic/elastic-agent/pkg/core/logger"
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

	if !action.Data.Unprivileged {
		// only unprivileged supported at this point
		return fmt.Errorf("unsupported action, ActionPrivilegeLevelChange supports only downgrading permissions")
	}

	// ensure no component issues
	err := componentvalidation.EnsureNoServiceComponentIssues()
	if err != nil {
		h.log.Debugf("handlerPrivilegeLevelChange: found issues with components: %v", err)
		return err
	}

	var username, groupname, password string
	if action.Data.UserInfo != nil {
		username = action.Data.UserInfo.Username
		groupname = action.Data.UserInfo.Groupname
		password = action.Data.UserInfo.Password
	}
	username, password = install.UnprivilegedUser(username, password)
	groupname = install.UnprivilegedGroup(groupname)

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
