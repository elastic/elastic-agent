// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestQuotaKindName(t *testing.T) {
	cases := map[QuotaKind]string{QuotaUnknown: "unknown", QuotaSkipped: "unknown", QuotaNone: "none", QuotaSet: "set"}
	for kind, want := range cases {
		require.Equal(t, want, kind.Name())
	}
}

func TestQuotaKindMarshalText(t *testing.T) {
	cases := map[QuotaKind]string{QuotaUnknown: "unknown", QuotaSkipped: "unknown", QuotaNone: "none", QuotaSet: "set"}
	for kind, want := range cases {
		t.Run(string(kind), func(t *testing.T) {
			got, err := json.Marshal(Quota{Kind: kind, CPUs: 2})
			require.NoError(t, err)
			require.JSONEq(t, `{"Kind":"`+want+`","CPUs":2}`, string(got))

			got, err = yaml.Marshal(Quota{Kind: kind, CPUs: 2})
			require.NoError(t, err)
			require.YAMLEq(t, "kind: "+want+"\ncpus: 2\n", string(got))
		})
	}
}

func TestQuotaKindKnown(t *testing.T) {
	cases := map[QuotaKind]bool{QuotaUnknown: false, QuotaSkipped: false, QuotaNone: true, QuotaSet: true}
	for kind, want := range cases {
		require.Equal(t, want, kind.Known(), "kind %q", kind)
	}
}
