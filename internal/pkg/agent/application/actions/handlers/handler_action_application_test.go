// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterActionData(t *testing.T) {
	data := json.RawMessage(`{"space_id":"default","step_id":"s1","request":{"headers":{"Authorization":"Bearer secret"}}}`)

	tests := map[string]struct {
		data   json.RawMessage
		fields []string
		want   string
	}{
		"keeps only listed fields": {
			data:   data,
			fields: []string{"space_id", "step_id", "execution_id"},
			want:   `{"space_id":"default","step_id":"s1"}`,
		},
		"empty list drops everything": {
			data: data,
			want: `{}`,
		},
		"non-object data is replaced": {
			data:   json.RawMessage(`"Bearer secret"`),
			fields: []string{"space_id"},
			want:   `{}`,
		},
		"missing data": {
			fields: []string{"space_id"},
			want:   `{}`,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := filterActionData(tc.data, tc.fields)
			assert.JSONEq(t, tc.want, string(got))
			assert.NotContains(t, string(got), "secret")
		})
	}
}
