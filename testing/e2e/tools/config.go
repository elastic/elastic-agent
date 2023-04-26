package tools

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

type ClusterConfig struct {
	ESConfig     ESConfig     `yaml:"elasticsearch"`
	KibanaConfig KibanaConfig `yaml:"kibana"`
	Users        []string     `yaml:"users"`
	FleetConfig  FleetConfig  `yaml:"fleet"`
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

type FleetConfig struct {
	ESApiToken      string `yaml:"ELASTICSEARCH_API_TOKEN"`
	FleetEsHost     string `yaml:"FLEET_ELASTICSEARCH_HOST"`
	EnrollmentToken string `yaml:"FLEET_ENROLLMENT_TOKEN"`
	PolicyId        string `yaml:"FLEET_SERVER_POLICY_ID"`
	ServiceToken    string `yaml:"FLEET_SERVER_SERVICE_TOKEN"`
	TokenPolicyName string `yaml:"FLEET_SERVER_TOKEN_POLICY_NAME"`
	Url             string `yaml:"FLEET_URL"`
}

func ReadConfig(clusterConfigPath string) (ClusterConfig, error) {
	absPath, _ := filepath.Abs(clusterConfigPath)
	data, err := os.ReadFile(absPath)

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
