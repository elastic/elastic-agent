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
	"github.com/elastic/elastic-agent/internal/pkg/agent/install/service"
	"github.com/elastic/elastic-agent/internal/pkg/config"
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

// Handle handles UNENROLL action.
func (h *PrivilegeLevelChange) Handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	return h.handle(ctx, a, acker)
}

func (h *PrivilegeLevelChange) handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) (rerr error) {
	h.log.Debugf("handlerPrivilegeLevelChange: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionPrivilegeLevelChange)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionPrivilegeLevelChange and received %T", a)
	}

	defer func() {
		if rerr != nil {
			h.log.Debugf("handlerPrivilegeLevelChange: acking failure: %v", rerr)
			h.ackFailure(ctx, rerr, action, acker)
		}
	}()

	if !action.Data.Unprivileged {
		// only unprivileged supported at this point
		return fmt.Errorf("unsupported action, ActionPrivilegeLevelChange supports only downgrading permissions")
	}

	// ensure no component issues
	err := service.EnsureNoServiceComponentIssues()
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

	h.log.Debugf("handlerPrivilegeLevelChange: proceeding with user %q and group %q", username, groupname)

	// apply empty config to stop processing
	unenrollPolicy := newPolicyChange(ctx, config.New(), a, acker, true, false)
	h.ch <- unenrollPolicy

	unenrollCtx, cancel := context.WithTimeout(ctx, unenrollTimeout)
	defer cancel()

	h.log.Debugf("handlerPrivilegeLevelChange: waiting for empty policy to take place")
	unenrollPolicy.WaitAck(unenrollCtx)

	// fix permissions
	topPath := paths.Top()
	h.log.Debugf("handlerPrivilegeLevelChange: fixing permissions from %v", topPath)
	_, err = install.SwitchServiceUser(topPath, &debugDescriber{h.log}, username, groupname, password)
	if err != nil {
		// error already adds context
		h.log.Debugf("handlerPrivilegeLevelChange: fixing failed with error: %v", err)
		return err
	}

	// ack
	if err := acker.Ack(ctx, a); err != nil {
		h.log.Errorf("failed to ACK an action: %w", err)
	}
	if err := acker.Commit(ctx); err != nil {
		h.log.Errorf("failed to commit ACK of an action: %w", err)
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

type noopDescriber struct{}

func (*noopDescriber) Describe(string) {}

type debugDescriber struct {
	l *logger.Logger
}

func (d *debugDescriber) Describe(a string) {
	d.l.Debug(a)
}
