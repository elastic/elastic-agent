// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package status

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/internal/pkg/core/state"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestNewController_ensure_all_is_initialzed(t *testing.T) {
	l, _ := logger.New("", false)

	newController := NewController(l)

	c, ok := newController.(*controller)
	if !ok {
		t.Fatalf("expected c %T, not c %T", controller{}, newController)
	}

	c.reporters["ignore"] = &reporter{}
	c.localReporters["ignore"] = &reporter{}
	c.appReporters["ignore"] = &reporter{}
	if c.log == nil {
		t.Error("logger shouldn't be nil, it was not correctly assigned")
	}
}

func TestReporter(t *testing.T) {
	l, _ := logger.New("", false)
	t.Run("healthy by default", func(t *testing.T) {
		r := NewController(l)
		assert.Equal(t, Healthy, r.StatusCode())
		assert.Equal(t, "online", r.StatusString())
	})

	t.Run("healthy when all healthy", func(t *testing.T) {
		r := NewController(l)
		r1 := r.RegisterComponent("r1")
		r2 := r.RegisterComponent("r2")
		r3 := r.RegisterComponent("r3")
		a1 := r.RegisterApp("app-1", "app")
		a2 := r.RegisterApp("app-2", "app")
		a3 := r.RegisterApp("other-1", "other")

		r1.Update(state.Healthy, "", nil)
		r2.Update(state.Healthy, "", nil)
		r3.Update(state.Healthy, "", nil)
		a1.Update(state.Healthy, "", nil)
		a2.Update(state.Healthy, "", nil)
		a3.Update(state.Healthy, "", nil)

		assert.Equal(t, Healthy, r.StatusCode())
		assert.Equal(t, "online", r.StatusString())
	})

	t.Run("degraded when one degraded", func(t *testing.T) {
		r := NewController(l)
		r1 := r.RegisterComponent("r1")
		r2 := r.RegisterComponent("r2")
		r3 := r.RegisterComponent("r3")

		r1.Update(state.Healthy, "", nil)
		r2.Update(state.Degraded, "degraded", nil)
		r3.Update(state.Healthy, "", nil)

		assert.Equal(t, Degraded, r.StatusCode())
		assert.Equal(t, "degraded", r.StatusString())
	})

	t.Run("failed when one failed", func(t *testing.T) {
		r := NewController(l)
		r1 := r.RegisterComponent("r1")
		r2 := r.RegisterComponent("r2")
		r3 := r.RegisterComponent("r3")

		r1.Update(state.Healthy, "", nil)
		r2.Update(state.Failed, "failed", nil)
		r3.Update(state.Healthy, "", nil)

		assert.Equal(t, Failed, r.StatusCode())
		assert.Equal(t, "error", r.StatusString())
	})

	t.Run("failed when one failed and one degraded", func(t *testing.T) {
		r := NewController(l)
		r1 := r.RegisterComponent("r1")
		r2 := r.RegisterComponent("r2")
		r3 := r.RegisterComponent("r3")

		r1.Update(state.Healthy, "", nil)
		r2.Update(state.Failed, "failed", nil)
		r3.Update(state.Degraded, "degraded", nil)

		assert.Equal(t, Failed, r.StatusCode())
		assert.Equal(t, "error", r.StatusString())
	})

	t.Run("degraded when degraded and healthy, failed unregistered", func(t *testing.T) {
		r := NewController(l)
		r1 := r.RegisterComponent("r1")
		r2 := r.RegisterComponent("r2")
		r3 := r.RegisterComponent("r3")

		r1.Update(state.Healthy, "", nil)
		r2.Update(state.Failed, "failed", nil)
		r3.Update(state.Degraded, "degraded", nil)

		r2.Unregister()

		assert.Equal(t, Degraded, r.StatusCode())
		assert.Equal(t, "degraded", r.StatusString())
	})

	t.Run("Check agent status components healthy", func(t *testing.T) {
		r := NewController(l)
		r1 := r.RegisterComponent("r1")
		r2 := r.RegisterComponent("r2")
		r3 := r.RegisterComponent("r3")

		r1.Update(state.Healthy, "", nil)
		r2.Update(state.Healthy, "", nil)
		r3.Update(state.Healthy, "", nil)

		s := r.Status()
		assert.Equal(t, Healthy, s.Status)
		assert.Equal(t, "", s.Message)
		assert.Equal(t, time.Time{}, s.UpdateTime)
	})

	//nolint:dupl // test case
	t.Run("Check agent status one component degraded", func(t *testing.T) {
		r := NewController(l)
		r1 := r.RegisterComponent("r1")
		r2 := r.RegisterComponent("r2")
		r3 := r.RegisterComponent("r3")

		r1.Update(state.Healthy, "", nil)
		r2.Update(state.Degraded, "degraded", nil)
		r3.Update(state.Healthy, "", nil)

		s := r.Status()
		assert.Equal(t, Degraded, s.Status)
		assert.Contains(t, s.Message, "component r2")
		assert.Contains(t, s.Message, "degraded")
		assert.NotEqual(t, time.Time{}, s.UpdateTime)
	})

	//nolint:dupl // test case
	t.Run("Check agent status one component failed", func(t *testing.T) {
		r := NewController(l)
		r1 := r.RegisterComponent("r1")
		r2 := r.RegisterComponent("r2")
		r3 := r.RegisterComponent("r3")

		r1.Update(state.Healthy, "", nil)
		r2.Update(state.Failed, "failed", nil)
		r3.Update(state.Degraded, "degraded", nil)

		s := r.Status()
		assert.Equal(t, Failed, s.Status)
		assert.Contains(t, s.Message, "component r2")
		assert.Contains(t, s.Message, "failed")
		assert.NotEqual(t, time.Time{}, s.UpdateTime)
	})
}
