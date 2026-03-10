package translate

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/stretchr/testify/require"
)

func TestKafkaTranslationLogic(t *testing.T) {

	testCases := []struct {
		name        string
		input       string
		expectedMap map[string]any
	}{{
		name: "basic kafka translation logic",
		input: `
	`,
		expectedMap: map[string]any{},
	}, {}}

	for _, testc := range testCases {
		t.Run(testc.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(testc.input)
			require.NoError(t, err, "error creating kafka config")
			gotMap, err := KafkaToOTelConfig(cfg, logp.NewNopLogger())
			require.NoError(t, err, "error translating kafka to kafka exporter")
			require.Equal(t, testc.expectedMap, gotMap)
		})
	}
}
