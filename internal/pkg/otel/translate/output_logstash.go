package translate

import (
	"fmt"

	"github.com/elastic/beats/v7/libbeat/outputs"
	"github.com/elastic/beats/v7/libbeat/outputs/logstash"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/go-viper/mapstructure/v2"
)

type logstashOutputConfig struct {
	outputs.HostWorkerCfg `config:",inline"`
	logstash.Config       `config:",inline"`
}

// LogstashToOTelConfig converts a Beat config into logstash exporter config
// Note: This method may override output queue settings defined by user.
func LogstashToOTelConfig(output *config.C, logger *logp.Logger) (map[string]any, error) {
	logstashConfig := logstashOutputConfig{
		Config: logstash.DefaultConfig(),
	}

	unpackedMap := make(map[string]any)
	if err := output.Unpack(&unpackedMap); err != nil {
		return nil, fmt.Errorf("failed unpacking config. %w", err)
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:          &logstashConfig,
		TagName:         "config",
		SquashTagOption: "inline",
		DecodeHook:      cfgDecodeHookFunc(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed creating decoder. %w", err)
	}

	err = decoder.Decode(&unpackedMap)
	if err != nil {
		return nil, fmt.Errorf("failed decoding config. %w", err)
	}

	// convert logstash config into a map
	var finalMap map[string]any
	lsConfig := config.MustNewConfigFrom(logstashConfig)
	lsConfig.Unpack(&finalMap)

	return finalMap, nil
}
