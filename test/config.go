package elastic_agent_e2e

import (
	"os"

	"gopkg.in/yaml.v2"
)

type ClusterConfig struct {
	ESConfig   ESConfig     `yaml:"elasticsearch"`
	KibanaConf KibanaConfig `yaml:"kibana"`
	Users      []string     `yaml:"users"`
}

type ESConfig struct {
	Host     string `yaml:"ELASTICSEARCH_HOST"`
	User     string `yaml:"ELASTICSEARCH_USERNAME"`
	Password string `yaml:"ELASTICSEARCH_PASSWORD"`
}

type KibanaConfig struct {
	Host     string `yaml:"KIBANA_HOST"`
	User     string `yaml:"KIBANA_USERNAME"`
	Password string `yaml:"KIBANA_PASSWORD"`
}

func ReadConfig(clusterConfigPath string) (ClusterConfig, error) {
	data, err := os.ReadFile(clusterConfigPath)

	if err != nil {
		panic(err)
	}
	var clusterConfig ClusterConfig
	err = yaml.Unmarshal(data, &clusterConfig)
	if err != nil {
		return ClusterConfig{}, err
	}
	return clusterConfig, nil
}
