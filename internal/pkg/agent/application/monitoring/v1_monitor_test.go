package monitoring

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	monitoringcfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
)

func TestMonitoringConfigMetricsInterval(t *testing.T) {

	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err, "Error creating agent info")

	mCfg := &monitoringConfig{
		C: &monitoringcfg.MonitoringConfig{
			Enabled:        true,
			MonitorMetrics: true,
			HTTP: &monitoringcfg.MonitoringHTTPConfig{
				Enabled: false,
			},
		},
	}

	policy := map[string]any{
		"agent": map[string]any{
			"monitoring": map[string]any{
				"metrics": true,
				"http": map[string]any{
					"enabled": false,
				},
			},
		},
		"outputs": map[string]any{
			"default": map[string]any{},
		},
	}
	b := &BeatsMonitor{
		enabled:         true,
		config:          mCfg,
		operatingSystem: runtime.GOOS,
		agentInfo:       agentInfo,
	}
	got, err := b.MonitoringConfig(policy, nil, map[string]string{"foobeat": "filebeat"}) // put a componentID/binary mapping to have something in the beats monitoring input
	assert.NoError(t, err)

	rawInputs, ok := got["inputs"]
	require.True(t, ok, "monitoring config contains no input")
	inputs, ok := rawInputs.([]any)
	require.True(t, ok, "monitoring inputs are not a list")
	marshaledInputs, err := yaml.Marshal(inputs)
	if assert.NoError(t, err, "error marshaling monitoring inputs") {
		t.Logf("marshaled monitoring inputs:\n%s\n", marshaledInputs)
	}

	// loop over the created inputs
	for _, i := range inputs {
		input, ok := i.(map[string]any)
		if assert.Truef(t, ok, "input is not represented as a map: %v", i) {
			inputID := input["id"]
			t.Logf("input %q", inputID)
			// check the streams created for the input, should be a list of objects
			if assert.Contains(t, input, "streams", "input %q does not contain any stream", inputID) &&
				assert.IsTypef(t, []any{}, input["streams"], "streams for input %q are not a list of objects", inputID) {
				// loop over streams and cast to map[string]any to access keys
				for _, rawStream := range input["streams"].([]any) {
					if assert.IsTypef(t, map[string]any{}, rawStream, "stream %v for input %q is not a map", rawStream, inputID) {
						stream := rawStream.(map[string]any)
						// check period and assert its value
						streamID := stream["id"]
						if assert.Containsf(t, stream, "period", "stream %q for input %q does not contain a period", streamID, inputID) &&
							assert.IsType(t, "", stream["period"], "period for stream %q of input %q is not represented as a string", streamID, inputID) {
							periodString := stream["period"].(string)
							duration, err := time.ParseDuration(periodString)
							if assert.NoErrorf(t, err, "Unparseable period duration %s for stream %q of input %q", periodString, streamID, inputID) {
								assert.Equalf(t, duration, 60*time.Second, "unexpected duration for stream %q of input %q", streamID, inputID)
							}
						}
					}
				}
			}
		}

	}
}
