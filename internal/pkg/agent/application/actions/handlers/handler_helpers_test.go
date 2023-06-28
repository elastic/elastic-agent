// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/component"
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

func TestDispatchActionInParallel(t *testing.T) {
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
			Name: "no components",
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

			err := dispatchActionInParallel(ctx, log, tc.Action, tc.UCs, tc.performAction)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
