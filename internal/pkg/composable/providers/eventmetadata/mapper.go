package eventmetadata

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
)

func mapGlobalProviderConfig(conf map[string]globalProviderConfig) (*proto.GlobalProcessorsConfig, error) {
	if len(conf) == 0 {
		// empty config need no mapping
		return nil, nil
	}

	configs := map[string]*proto.ProcessorConfig{}

	for providerName, providerConfig := range conf {
		protoConfig, err := structpb.NewStruct(providerConfig.Config)
		if err != nil {
			return nil, fmt.Errorf("marshaling config for provider %s: %w", providerName, err)
		}

		processorConfig := &proto.ProcessorConfig{
			Enabled: providerConfig.Enabled,
			Config:  protoConfig,
		}

		configs[providerName] = processorConfig
	}

	gpc := &proto.GlobalProcessorsConfig{
		Configs: configs,
	}
	source, err := toSource(map[string]any{"configs": conf})
	if err != nil {
		return nil, fmt.Errorf("creating source: %w", err)
	}
	gpc.Source = source
	return gpc, nil
}

func toSource(m any) (*structpb.Struct, error) {
	sourceMap := map[string]any{}
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshaling configs to json: %w", err)
	}
	err = json.Unmarshal(jsonBytes, &sourceMap)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling json bytes to create source field: %w", err)
	}

	return structpb.NewStruct(sourceMap)
}
