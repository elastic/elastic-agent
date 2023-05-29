// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"fmt"
	"path"
	"strings"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

const (
	// LayoutIntegrationTag is the tag added to all layouts for the integration testing framework.
	LayoutIntegrationTag = "agent-integration"
)

// LayoutBatch defines the mapping between a LayoutOS and a define.Batch.
type LayoutBatch struct {
	// ID is the unique ID for the layout/batch.
	ID string
	// LayoutOS provides all the OS information to create an instance.
	LayoutOS LayoutOS
	// Batch defines the batch of tests to run on this layout.
	Batch define.Batch
	// Skip defines if this batch will be skipped because no supported layout exists yet.
	Skip bool
}

// toOGC converts this layout batch into a layout for OGC.
func (lb *LayoutBatch) toOGC() OGCLayout {
	tags := []string{
		LayoutIntegrationTag,
		lb.LayoutOS.OS.Type,
		lb.LayoutOS.OS.Arch,
		strings.ToLower(fmt.Sprintf("%s-%s", lb.LayoutOS.OS.Distro, strings.Replace(lb.LayoutOS.OS.Version, ".", "-", -1))),
	}
	if lb.Batch.Isolate {
		tags = append(tags, "isolate")
		var test define.BatchPackageTests
		if len(lb.Batch.SudoTests) > 0 {
			test = lb.Batch.SudoTests[0]
		} else if len(lb.Batch.Tests) > 0 {
			test = lb.Batch.Tests[0]
		}
		tags = append(tags, fmt.Sprintf("%s-%s", path.Base(test.Name), strings.ToLower(test.Tests[0])))
	}
	return OGCLayout{
		Name:          lb.ID,
		Provider:      lb.LayoutOS.Provider,
		InstanceSize:  lb.LayoutOS.InstanceSize,
		RunsOn:        lb.LayoutOS.RunsOn,
		RemotePath:    lb.LayoutOS.RemotePath,
		Scale:         1,
		Username:      lb.LayoutOS.Username,
		SSHPrivateKey: ".ogc-cache/id_rsa",
		SSHPublicKey:  ".ogc-cache/id_rsa.pub",
		Ports:         []string{"22:22"},
		Tags:          tags,
		Labels: map[string]string{
			"division": "engineering",
			"org":      "platform",
			"team":     "ingest",
			"project":  "elastic-agent",
		},
		Scripts: "path", // not used; but required by OGC
	}
}
