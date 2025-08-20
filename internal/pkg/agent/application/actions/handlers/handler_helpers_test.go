// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

type testAction struct {
	typ  string
	data map[string]interface{}
}

func (a testAction) Type() string {
	return a.typ
}

func (a testAction) MarshalMap() (map[string]interface{}, error) {
	return a.data, nil
}

func TestNotifyUnitsOfProxiedAction(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	log := logp.NewLogger("testing")

	happyPerformAction := func(context.Context, component.Component, component.Unit, string, map[string]interface{}) (map[string]interface{}, error) {
		return nil, nil
	}

	tests := []struct {
		Name          string
		Action        dispatchableAction
		UCs           []unitWithComponent
		performAction performActionFunc
	}{
		{
			Name: "nil action",
		},
		{
			Name: "no components",
			Action: testAction{
				typ: "UNENROLL",
			},
		},
		{
			Name: "one component",
			Action: testAction{
				typ: "UNENROLL",
			},
			UCs: []unitWithComponent{
				{
					component: component.Component{},
					unit: component.Unit{
						Config: &proto.UnitExpectedConfig{
							Type: "endpoint",
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.performAction == nil {
				tc.performAction = happyPerformAction
			}

			err := notifyUnitsOfProxiedAction(ctx, log, tc.Action, tc.UCs, tc.performAction)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

type mockActionPerformer struct {
	calledTimes     int
	shouldFailTimes int
}

var errPerformActionFail = errors.New("perform action failed")

func (p *mockActionPerformer) PerformAction(context.Context, component.Component, component.Unit, string, map[string]interface{}) (map[string]interface{}, error) {
	p.calledTimes++
	if p.calledTimes < p.shouldFailTimes {
		return nil, errPerformActionFail
	}
	return nil, nil
}

type ActionPerformer interface {
	PerformAction(context.Context, component.Component, component.Unit, string, map[string]interface{}) (map[string]interface{}, error)
}

func TestProxiedActionsNotifier(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()
	log := logp.NewLogger("testing")

	tests := []struct {
		RetryTimeout    time.Duration
		RetryMinBackoff time.Duration

		Name                         string
		Action                       dispatchableAction
		UCs                          []unitWithComponent
		ActionPerformer              mockActionPerformer
		WantActionPerformCalledTimes int
		WantErr                      error
	}{
		{
			Name: "nil action",
		},
		{
			Name: "no components",
			Action: testAction{
				typ: "UNENROLL",
			},
		},
		{
			Name: "one component, success",
			Action: testAction{
				typ: "UNENROLL",
			},
			UCs: []unitWithComponent{
				{
					component: component.Component{},
					unit: component.Unit{
						Config: &proto.UnitExpectedConfig{
							Type: "endpoint",
						},
					},
				},
			},
			WantActionPerformCalledTimes: 1,
		},
		{
			Name: "one component, failing, timeout",
			Action: testAction{
				typ: "UNENROLL",
			},
			ActionPerformer: mockActionPerformer{shouldFailTimes: math.MaxInt64},
			RetryMinBackoff: 300 * time.Millisecond,
			RetryTimeout:    400 * time.Millisecond,
			UCs: []unitWithComponent{
				{
					component: component.Component{},
					unit: component.Unit{
						Config: &proto.UnitExpectedConfig{
							Type: "endpoint",
						},
					},
				},
			},
			WantActionPerformCalledTimes: 1,
			WantErr:                      errPerformActionFail,
		},
		{
			Name: "one component, retrying, succeeds",
			Action: testAction{
				typ: "UNENROLL",
			},
			ActionPerformer: mockActionPerformer{shouldFailTimes: 2},
			RetryMinBackoff: 200 * time.Millisecond,
			RetryTimeout:    1 * time.Second,
			UCs: []unitWithComponent{
				{
					component: component.Component{},
					unit: component.Unit{
						Config: &proto.UnitExpectedConfig{
							Type: "endpoint",
						},
					},
				},
			},
			WantActionPerformCalledTimes: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			d := newProxiedActionsNotifier(log, tc.ActionPerformer.PerformAction)
			if tc.RetryTimeout != 0 {
				d.timeout = tc.RetryTimeout
			}
			if tc.RetryMinBackoff != 0 {
				d.minBackoff = tc.RetryMinBackoff
			}
			err := d.notify(ctx, tc.Action, tc.UCs)
			diff := cmp.Diff(tc.WantErr, err, cmpopts.EquateErrors())
			if diff != "" {
				t.Fatal(diff)
			}

			diff = cmp.Diff(tc.WantActionPerformCalledTimes, tc.ActionPerformer.calledTimes)
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestSaveConfigToStore(t *testing.T) {
	// Create destination file
	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "dest.txt")
	err := os.WriteFile(dest, []byte("existing content"), 0644)
	require.NoError(t, err)

	// Open handle on destination file and keep it open for a random duration
	// between [200ms, 1800ms).
	openDuration := time.Duration(200+rand.Int64N(1800-200)) * time.Millisecond
	destFile, err := os.Open(dest)
	require.NoError(t, err)
	time.AfterFunc(openDuration, func() {
		destFile.Close()
	})
	defer destFile.Close()

	// Create disk store
	store, err := storage.NewDiskStore(dest)
	require.NoError(t, err)

	// Try to save content to store
	reader := strings.NewReader("new content")
	log, _ := loggertest.New("test")
	err = saveConfigToStore(store, reader, log)
	require.NoError(t, err)

	// Check that dest file has been replaced with new file
	data, err := os.ReadFile(dest)
	require.NoError(t, err)
	require.Equal(t, "new content", string(data))
}
