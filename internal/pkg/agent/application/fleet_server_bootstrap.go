// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	elasticsearch = "elasticsearch"
	fleetServer   = "fleet-server"
	endpoint      = "endpoint"
	apmServer     = "apm"
)

// ErrFleetServerNotBootstrapped set on fleet-server component and units when the Elastic Agent has not been
// bootstrapped with the required command-line arguments for the Elastic Agent to be able to run the Fleet Server.
var ErrFleetServerNotBootstrapped = errors.New("elastic-agent must be bootstrapped with a fleet-server; re-install or re-enroll with --fleet-server-* options")

// injectFleetServerInput is the base configuration that is used plus the FleetServerComponentModifier that adjusts
// the components before sending them to the runtime manager.
var injectFleetServerInput = config.MustNewConfigFrom(map[string]interface{}{
	"outputs": map[string]interface{}{
		"default": map[string]interface{}{
			"type":  elasticsearch,
			"hosts": []string{"localhost:9200"},
		},
	},
	"inputs": []interface{}{
		map[string]interface{}{
			"id":   fleetServer,
			"type": fleetServer,
		},
	},
})

// FleetServerComponentModifier modifies the comps to inject extra information from the policy into
// the Fleet Server component and units needed to run Fleet Server correctly.
func FleetServerComponentModifier(serverCfg *configuration.FleetServerConfig) coordinator.ComponentsModifier {
	return func(comps []component.Component, _ map[string]interface{}) ([]component.Component, error) {
		for i, comp := range comps {
			if comp.InputSpec != nil && comp.InputSpec.InputType == fleetServer && comp.Err == nil {
				if serverCfg == nil {
					// Elastic Agent was bootstrapped without a Fleet Server so enabling a Fleet Server is not
					// supported. The Elastic Agent needs to be re-enrolled to run a Fleet Server.
					comp.Err = ErrFleetServerNotBootstrapped
					for j, unit := range comp.Units {
						unit.Err = ErrFleetServerNotBootstrapped
						comp.Units[j] = unit
					}
				} else {
					for j, unit := range comp.Units {
						if unit.Type == client.UnitTypeOutput && unit.Config.Type == elasticsearch {
							unitCfgMap, err := toMapStr(unit.Config.Source.AsMap(), &serverCfg.Output.Elasticsearch)
							if err != nil {
								return nil, err
							}
							fixOutputMap(unitCfgMap)
							unitCfg, err := component.ExpectedConfig(unitCfgMap)
							if err != nil {
								return nil, err
							}
							unit.Config = unitCfg
						} else if unit.Type == client.UnitTypeInput && unit.Config.Type == fleetServer {
							unitCfgMap, err := toMapStr(unit.Config.Source.AsMap(), &inputFleetServer{
								Policy: serverCfg.Policy,
								Server: serverCfg,
							})
							if err != nil {
								return nil, err
							}
							fixInputMap(unitCfgMap)
							unitCfg, err := component.ExpectedConfig(unitCfgMap)
							if err != nil {
								return nil, err
							}
							unit.Config = unitCfg
						}
						comp.Units[j] = unit
					}
				}
			}
			comps[i] = comp
		}
		return comps, nil
	}
}

// InjectFleetConfigComponentModifier The modifier that injects the fleet configuration for the components
// that need to be able to connect to fleet server.
func InjectFleetConfigComponentModifier(fleetCfg *configuration.FleetAgentConfig, agentInfo *info.AgentInfo) coordinator.ComponentsModifier {
	return func(comps []component.Component, cfg map[string]interface{}) ([]component.Component, error) {
		hostsStr := fleetCfg.Client.GetHosts()
		fleetHosts := make([]interface{}, 0, len(hostsStr))
		for _, host := range hostsStr {
			fleetHosts = append(fleetHosts, host)
		}

		for i, comp := range comps {
			if comp.InputSpec != nil && (comp.InputSpec.InputType == endpoint || comp.InputSpec.InputType == apmServer) {
				for j, unit := range comp.Units {
					if unit.Type == client.UnitTypeInput && (unit.Config.Type == endpoint || unit.Config.Type == apmServer) {
						unitCfgMap, err := toMapStr(unit.Config.Source.AsMap(), map[string]interface{}{"fleet": fleetCfg})
						if err != nil {
							return nil, err
						}
						// Set host.id for the host, assign the host from the top level config
						// Endpoint expects this
						// "host": {
						// 	   "id": "b62e91be682a4108bbb080152cc5eeac"
						// },
						if v, ok := unitCfgMap["fleet"]; ok {
							if m, ok := v.(map[string]interface{}); ok {
								m["host"] = cfg["host"]
								m["hosts"] = fleetHosts

								// Inject agent log level
								injectAgentLoggingLevel(m, agentInfo)
							}
						}
						unitCfg, err := component.ExpectedConfig(unitCfgMap)
						if err != nil {
							return nil, err
						}
						unit.Config = unitCfg
					}
					comp.Units[j] = unit
				}
			}
			comps[i] = comp
		}
		return comps, nil
	}
}

type logLevelProvider interface {
	LogLevel() string
}

func injectAgentLoggingLevel(cfg map[string]interface{}, llp logLevelProvider) {
	if cfg == nil || llp == nil {
		return
	}

	var agentMap, loggingMap map[string]interface{}
	if v, ok := cfg["agent"]; ok {
		agentMap, _ = v.(map[string]interface{})
	} else {
		agentMap = make(map[string]interface{})
		cfg["agent"] = agentMap
	}

	if agentMap != nil {
		if v, ok := agentMap["logging"]; ok {
			loggingMap, _ = v.(map[string]interface{})
		} else {
			loggingMap = make(map[string]interface{})
			agentMap["logging"] = loggingMap
		}
	}

	if loggingMap != nil {
		loggingMap["level"] = llp.LogLevel()
	}
}

type fleetServerBootstrapManager struct {
	log *logger.Logger

	ch    chan coordinator.ConfigChange
	errCh chan error
}

func newFleetServerBootstrapManager(
	log *logger.Logger,
) *fleetServerBootstrapManager {
	return &fleetServerBootstrapManager{
		log:   log,
		ch:    make(chan coordinator.ConfigChange),
		errCh: make(chan error),
	}
}

func (m *fleetServerBootstrapManager) Run(ctx context.Context) error {
	m.log.Debugf("injecting fleet-server for bootstrap")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.ch <- &localConfigChange{injectFleetServerInput}:
	}

	<-ctx.Done()
	return ctx.Err()
}

func (m *fleetServerBootstrapManager) Errors() <-chan error {
	return m.errCh
}

func (m *fleetServerBootstrapManager) ActionErrors() <-chan error {
	return nil
}

func (m *fleetServerBootstrapManager) Watch() <-chan coordinator.ConfigChange {
	return m.ch
}

func fixOutputMap(m map[string]interface{}) {
	// api_key cannot be present or Fleet Server will complain
	delete(m, "api_key")
}

type inputFleetServer struct {
	Policy *configuration.FleetServerPolicyConfig `yaml:"policy,omitempty"`
	Server *configuration.FleetServerConfig       `yaml:"server"`
}

func fixInputMap(m map[string]interface{}) {
	if srv, ok := m["server"]; ok {
		if srvMap, ok := srv.(map[string]interface{}); ok {
			// bootstrap is internal to Elastic Agent
			delete(srvMap, "bootstrap")
			// policy is present one level input when sent to Fleet Server
			delete(srvMap, "policy")
			// output is present in the output unit
			delete(srvMap, "output")
		}
	}
}

// toMapStr converts the input into a map[string]interface{}.
//
// This is done by using YAMl to marshal and then unmarshal it into the map[string]interface{}. YAML tags on the struct
// match the loading and unloading of the configuration so this ensures that it will match what Fleet Server is
// expecting.
func toMapStr(input ...interface{}) (map[string]interface{}, error) {
	m := map[interface{}]interface{}{}
	for _, i := range input {
		im, err := toMapInterface(i)
		if err != nil {
			return nil, err
		}
		m = mergeNestedMaps(m, im)
	}
	// toMapInterface will set nested maps to a map[interface{}]interface{} which `component.ExpectedConfig` cannot
	// handle they must be a map[string]interface{}.
	fm := fixYamlMap(m)
	r, ok := fm.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("expected map[string]interface{}, got %T", fm)
	}
	return r, nil
}

// toMapInterface converts the input into a map[interface{}]interface{} using YAML marshall and unmarshall.
func toMapInterface(input interface{}) (map[interface{}]interface{}, error) {
	var res map[interface{}]interface{}
	raw, err := yaml.Marshal(input)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(raw, &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// mergeNestedMaps merges two map[interface{}]interface{} together deeply.
func mergeNestedMaps(a, b map[interface{}]interface{}) map[interface{}]interface{} {
	res := make(map[interface{}]interface{}, len(a))
	for k, v := range a {
		res[k] = v
	}
	for k, v := range b {
		if v, ok := v.(map[interface{}]interface{}); ok {
			if bv, ok := res[k]; ok {
				if bv, ok := bv.(map[interface{}]interface{}); ok {
					res[k] = mergeNestedMaps(bv, v)
					continue
				}
			}
		}
		res[k] = v
	}
	return res
}

// fixYamlMap converts map[interface{}]interface{} into map[string]interface{} through out the entire map.
func fixYamlMap(input interface{}) interface{} {
	switch i := input.(type) {
	case map[string]interface{}:
		for k, v := range i {
			i[k] = fixYamlMap(v)
		}
	case map[interface{}]interface{}:
		m := map[string]interface{}{}
		for k, v := range i {
			if ks, ok := k.(string); ok {
				m[ks] = fixYamlMap(v)
			}
		}
		return m
	case []interface{}:
		for j, v := range i {
			i[j] = fixYamlMap(v)
		}
	}
	return input
}
