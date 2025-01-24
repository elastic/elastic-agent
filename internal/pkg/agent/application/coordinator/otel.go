package coordinator

import (
	"errors"
	"fmt"
	"github.com/elastic/beats/v7/libbeat/outputs/elasticsearch"
	"github.com/elastic/beats/v7/x-pack/libbeat/management"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/go-viper/mapstructure/v2"
	"go.opentelemetry.io/collector/confmap"
	"slices"
	"strings"
)

type AgentConfig struct {
	Outputs map[string]struct {
		Type   string
		Config map[string]any `mapstructure:",remain"`
	} `mapstructure:"outputs"`

	Inputs []struct {
		UseOutput  string         `mapstructure:"use_output"`
		Type       string         `mapstructure:"type"`
		UnitConfig map[string]any `mapstructure:",remain"`
	} `mapstructure:"inputs"`
}

func getBeatName(inputType string) string {
	switch inputType {
	case "filestream":
		return "filebeat"
	default:
	}
	return ""
}

func toOtelReceiverName(beatName string) string {
	return strings.ToLower(beatName) + "receiver"
}

func getOtelConfig(cfg map[string]any, info info.Agent) (*confmap.Conf, error) {
	agentCfg := &AgentConfig{}
	err := mapstructure.Decode(cfg, agentCfg)
	if err != nil {
		return nil, err
	}
	exportersConfig, err := getOtelExportersConfig(agentCfg)
	if err != nil {
		return nil, err
	}
	inputs, err := getSupportedInputs(agentCfg)
	if err != nil {
		return nil, err
	}
	receiversConfig := map[string]any{}
	for _, input := range inputs {
		unitReceiversConfig, err := unitToReceiverConfigs(input, info)
		if err != nil {
			return nil, err
		}
		for k, v := range unitReceiversConfig {
			receiversConfig[k] = v
		}
	}

	receiverToExporter := getReceiverToExporterMap(agentCfg)
	pipelines := map[string]any{}
	for receiverId, exporterId := range receiverToExporter {
		pipelineId := fmt.Sprintf("logs/%s", receiverId)
		pipelines[pipelineId] = map[string][]string{
			"receivers": {receiverId},
			"exporters": {exporterId},
		}
	}
	rawConfig := map[string]any{
		"receivers": receiversConfig,
		"exporters": exportersConfig,
		"service": map[string]any{
			"pipelines": pipelines,
		},
	}
	return confmap.NewFromStringMap(rawConfig), nil
}

func getOtelExportersConfig(agentCfg *AgentConfig) (map[string]any, error) {
	if agentCfg.Outputs == nil {
		return nil, errors.New("no outputs present")
	}

	esOutputs := map[string]map[string]any{}
	for name, output := range agentCfg.Outputs {
		if output.Type == "elasticsearch" {
			esOutputs[name] = output.Config
		}
	}

	if len(esOutputs) == 0 {
		return nil, errors.New("no elasticsearch outputs present")
	}

	exportersCfg := map[string]any{}
	for name, outputCfg := range esOutputs {
		exporterName := fmt.Sprintf("elasticsearch/%s", name)
		outputCfgC, err := config.NewConfigFrom(outputCfg)
		if err != nil {
			return nil, err
		}
		esExporterConfig, err := elasticsearch.ToOTelConfig(outputCfgC)
		if err != nil {
			return nil, err
		}
		exportersCfg[exporterName] = esExporterConfig
	}

	return exportersCfg, nil
}

func getSupportedOutputNames(agentCfg *AgentConfig) []string {
	if agentCfg.Outputs == nil {
		return []string{}
	}

	var outputNames []string
	for name, output := range agentCfg.Outputs {
		if output.Type == "elasticsearch" {
			outputNames = append(outputNames, name)
		}
	}

	return outputNames
}

func getSupportedInputs(agentCfg *AgentConfig) ([]*proto.UnitExpectedConfig, error) {
	supportedOutputNames := getSupportedOutputNames(agentCfg)

	var supportedInputs []*proto.UnitExpectedConfig
	for _, input := range agentCfg.Inputs {
		if input.Type == "filestream" && slices.Contains(supportedOutputNames, input.UseOutput) {
			input.UnitConfig["type"] = input.Type
			unitExpectedConfig, err := component.ExpectedConfig(input.UnitConfig)
			if err != nil {
				return nil, err
			}
			supportedInputs = append(supportedInputs, unitExpectedConfig)
		}
	}
	return supportedInputs, nil
}

func unitToReceiverConfigs(unitCfg *proto.UnitExpectedConfig, info info.Agent) (map[string]any, error) {
	agentInfo := &client.AgentInfo{
		ID:           info.AgentID(),
		Version:      info.Version(),
		Snapshot:     info.Snapshot(),
		ManagedMode:  runtime.ProtoAgentMode(info),
		Unprivileged: info.Unprivileged(),
	}
	inputs, err := management.CreateInputsFromStreams(unitCfg, "logs", agentInfo)
	if err != nil {
		return nil, err
	}

	beatName := getBeatName(unitCfg.Type)
	receiverName := toOtelReceiverName(beatName)
	receiverId := fmt.Sprintf("%s/%s", receiverName, unitCfg.Id)
	receiverConfigs := map[string]any{}
	receiverConfig := map[string]any{
		beatName: map[string]any{
			"inputs": inputs,
		},
		"output": map[string]any{
			"otelconsumer": map[string]any{},
		},
	}
	receiverConfigs[receiverId] = receiverConfig
	return receiverConfigs, nil
}

func getReceiverToExporterMap(agentCfg *AgentConfig) map[string]string {
	supportedOutputNames := getSupportedOutputNames(agentCfg)
	outputMap := map[string]string{}
	for _, input := range agentCfg.Inputs {
		if input.Type == "filestream" && slices.Contains(supportedOutputNames, input.UseOutput) {
			exporterId := fmt.Sprintf("elasticsearch/%s", input.UseOutput)
			beatName := getBeatName(input.Type)
			receiverName := toOtelReceiverName(beatName)
			receiverId := fmt.Sprintf("%s/%s", receiverName, input.UnitConfig["id"])
			outputMap[receiverId] = exporterId
		}
	}
	return outputMap
}
