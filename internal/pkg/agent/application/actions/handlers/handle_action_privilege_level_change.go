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

func (h *PrivilegeLevelChange) handle(ctx context.Context, a fleetapi.Action, acker acker.Acker) error {
	h.log.Debugf("handlerPrivilegeLevelChange: action '%+v' received", a)
	action, ok := a.(*fleetapi.ActionPrivilegeLevelChange)
	if !ok {
		return fmt.Errorf("invalid type, expected ActionPrivilegeLevelChange and received %T", a)
	}

	if !action.Data.Unprivileged {
		// only unprivileged supported at this point
		return fmt.Errorf("unsupported action, ActionPrivilegeLevelChange supports only downgrading permissions")
	}

	// ensure no component issues
	err := service.EnsureNoServiceComponentIssues()
	if err != nil {
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
	unenrollPolicy := newPolicyChange(ctx, config.New(), a, acker, true)
	h.ch <- unenrollPolicy

	unenrollCtx, cancel := context.WithTimeout(ctx, unenrollTimeout)
	defer cancel()

	unenrollPolicy.WaitAck(unenrollCtx)

	// fix permissions
	topPath := paths.Top()
	err = install.SwitchExecutingMode(topPath, &noopDescriber{}, username, groupname, password)
	if err != nil {
		// error already adds context
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

type noopDescriber struct{}

func (*noopDescriber) Describe(string) {}
