// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mitchellh/mapstructure"
)

func TestConfigDeserializer(t *testing.T) {

	m := map[string]interface{}{
		"enabled":              true,
		"uninstall_token_hash": "ABCDEFG",
		"signing_key":          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEahHlKqDRfAcOZn0DmQBC7nQ8MS7CBNd8TAvBRlZl/MILX0GVsyzUmOjo+icMx+Quv7X/qVFlNjHhuBIp+7/AGA==",
	}

	var cfgSer configDeserializer
	err := mapstructure.Decode(m, &cfgSer)
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(cfgSer.Enabled, m["enabled"])
	if diff != "" {
		t.Fatal(diff)
	}
	diff = cmp.Diff(cfgSer.SigningKey, m["signing_key"])
	if diff != "" {
		t.Fatal(diff)
	}
	diff = cmp.Diff(cfgSer.UninstallTokenHash, m["uninstall_token_hash"])
	if diff != "" {
		t.Fatal(diff)
	}
}
