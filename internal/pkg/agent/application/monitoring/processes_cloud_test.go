package monitoring

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/pkg/component"
)

func TestExpectedCloudProcessID(t *testing.T) {
	testcases := []struct {
		name      string
		component component.Component
		id        string
	}{
		{
			"APM",
			component.Component{
				ID:        "apm-default",
				InputSpec: &component.InputRuntimeSpec{BinaryName: "apm-server"},
			},
			"apm-server",
		},
		{
			"NotAPM",
			component.Component{
				ID:        "filestream-default",
				InputSpec: &component.InputRuntimeSpec{BinaryName: "filebeat"},
			},
			"filestream-default",
		},
		{
			"AlmostAPM",
			component.Component{
				ID:        "apm-java-attacher-default",
				InputSpec: &component.InputRuntimeSpec{BinaryName: "apm-java-attacher"},
			},
			"apm-java-attacher-default",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.id, expectedCloudProcessID(&tc.component))
		})
	}
}

func TestMatchesCloudProcessID(t *testing.T) {
	testcases := []struct {
		name      string
		processID string
		component component.Component
		matches   bool
	}{
		{
			"MatchesAPMServer",
			"apm-server",
			component.Component{
				ID:        "apm-default",
				InputSpec: &component.InputRuntimeSpec{BinaryName: "apm-server"},
			},
			true,
		},
		{
			"MatchesAPMDefault",
			"apm-default",
			component.Component{
				ID:        "apm-default",
				InputSpec: &component.InputRuntimeSpec{BinaryName: "apm-server"},
			},
			true,
		},
		{
			"MatchesFilestream",
			"filestream-default",
			component.Component{
				ID:        "filestream-default",
				InputSpec: &component.InputRuntimeSpec{BinaryName: "filebeat"},
			},
			true,
		},
		{
			"DoesNotMatch",
			"filestream-default",
			component.Component{
				ID:        "metricbeat-default",
				InputSpec: &component.InputRuntimeSpec{BinaryName: "metricbeat"},
			},
			false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.matches, matchesCloudProcessID(&tc.component, tc.processID))
		})
	}
}
